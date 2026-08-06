//! Notifying downstream servers.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use cascade_zonedata::OldRecord;
use domain::{
    base::{MessageBuilder, Name, Rtype, iana::Opcode},
    net::client::{
        dgram,
        protocol::UdpConnect,
        request::{RequestMessage, SendRequest},
        tsig,
    },
};
use tracing::{debug, trace, warn};

use crate::{center::Center, policy::NameserverCommsPolicy, zonedata::SoaRecord};

pub fn send_notify_to_addrs<'a>(
    apex_name: Name<Bytes>,
    soa: SoaRecord,
    notify_set: impl Iterator<Item = &'a NameserverCommsPolicy>,
    center: &Arc<Center>,
) {
    let mut dgram_config = domain::net::client::dgram::Config::new();
    dgram_config.set_max_parallel(1);
    dgram_config.set_read_timeout(Duration::from_millis(1000));
    dgram_config.set_max_retries(1);
    dgram_config.set_udp_payload_size(Some(1400));

    let mut msg = MessageBuilder::new_vec();
    msg.header_mut().set_opcode(Opcode::NOTIFY);
    let mut msg = msg.question();
    msg.push((apex_name, Rtype::SOA)).unwrap();

    // Include the current zone SOA as an RFC 1996 "unsecure hint" (see
    // section 3.7) to the receiving nameserver so that it can choose to avoid
    // sending a SOA query if it deems that it has this version of the zone
    // already.
    let mut msg = msg.answer();
    msg.push(OldRecord::from(soa)).unwrap();

    for nameserver in notify_set {
        let dgram_config = dgram_config.clone();
        let req = RequestMessage::new(msg.clone()).unwrap();

        let nameserver = nameserver.clone();
        let center = center.clone();
        tokio::spawn(async move {
            // TODO: Use the connection factory here.
            let udp_connect = UdpConnect::new(nameserver.addr);
            let client = dgram::Connection::with_config(udp_connect, dgram_config.clone());

            trace!("Sending NOTIFY to nameserver {nameserver}");
            let span = tracing::trace_span!("auth", addr = %nameserver);
            let _guard = span.enter();

            // https://datatracker.ietf.org/doc/html/rfc1996
            //   "4.8 Master Receives a NOTIFY Response from Slave
            //
            //    When a master server receives a NOTIFY response, it deletes this
            //    query from the retry queue, thus completing the "notification
            //    process" of "this" RRset change to "that" server."
            //
            // TODO: We have no retry queue at the moment. Do we need one?

            let tsig_key = {
                let state = center.state.lock().unwrap();
                nameserver
                    .tsig_key_name
                    .as_ref()
                    .and_then(|tsig_key_name| state.tsig_store.get(tsig_key_name))
                    .map(|key| key.inner.clone())
            };

            if let Some(key) = &tsig_key {
                debug!(
                    "Found TSIG key '{}' (algorithm {}) for NOTIFY to {nameserver}",
                    key.name(),
                    key.algorithm()
                );
            }
            let res = if let Some(key) = tsig_key {
                let client = tsig::Connection::new(key.clone(), client);
                client.send_request(req.clone()).get_response().await
            } else {
                client.send_request(req.clone()).get_response().await
            };

            if let Err(err) = res {
                warn!("Unable to send NOTIFY to nameserver {nameserver}: {err}");
            }
        });
    }
}
