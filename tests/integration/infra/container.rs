//! Docker container control.

use std::{
    collections::HashMap,
    fmt,
    io::{BufWriter, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::SystemTime,
};

use bollard::{
    Docker,
    plugin::{ContainerCreateBody, ContainerCreateResponse, HostConfig, Mount, MountType},
    query_parameters::{
        CreateContainerOptions, DownloadFromContainerOptionsBuilder, RemoveContainerOptionsBuilder,
    },
};
use bytes::Bytes;
use domain::{
    base::{Message, MessageBuilder, Name, Rtype},
    net::client::request::{RequestMessage, RequestMessageMulti, SendRequest, SendRequestMulti},
    tsig,
};
use futures_util::StreamExt;
use tracing::Instrument;

use super::{Image, ports, strs};

#[cfg(doc)]
use super::TestConfig;

//----------- ContainerBuilder -------------------------------------------------

/// A builder for starting a new [`Container`].
pub struct ContainerBuilder<'image> {
    /// The image to build on.
    image: &'image Image,

    /// A name to assign the container.
    name: Option<Box<str>>,

    /// The path to the Cascade daemon binary.
    ///
    /// By default, fetched from the `CARGO_BIN_EXE_cascaded` env var.
    daemon_path: Option<Box<str>>,

    /// Environment variables to set in the container.
    ///
    /// [`None`] explicitly unsets a variables.
    env: HashMap<Box<str>, Option<Box<str>>>,
}

impl<'image> ContainerBuilder<'image> {
    /// Construct a new [`ContainerBuilder`].
    pub fn new(image: &'image Image) -> Self {
        Self {
            image,
            name: None,
            daemon_path: None,
            env: HashMap::from_iter([("RUST_BACKTRACE".into(), Some("1".into()))]),
        }
    }

    /// Set a name for the container.
    #[expect(dead_code)]
    pub fn name(mut self, name: impl Into<Box<str>>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Add an environment variable.
    #[expect(dead_code)]
    pub fn env(mut self, key: impl Into<Box<str>>, value: impl Into<Box<str>>) -> Self {
        let _ = self.env.insert(key.into(), Some(value.into()));
        self
    }

    /// Build a container using this configuration.
    pub fn build(&self) -> impl Future<Output = Container> + Send + use<> {
        let docker = self.image.docker.clone();
        let image_name = self.image.name.clone();
        let name = self.name.clone();

        let daemon_path = self.daemon_path.clone().unwrap_or_else(|| {
            std::env::var("CARGO_BIN_EXE_cascaded")
                .expect("Cargo sets `CARGO_BIN_EXE_cascaded` automatically")
                .into()
        });

        let env = self
            .env
            .iter()
            .map(|(k, v)| match v {
                Some(v) => format!("{k}={v}"),
                None => format!("{k}"),
            })
            .collect::<Vec<_>>();

        let span = tracing::debug_span!("build_container");
        async move {
            // Expose all known ports.
            let exposed_ports = ports::all()
                .into_iter()
                .map(|p| format!("{p}"))
                .collect::<Vec<_>>();

            let options = Some(CreateContainerOptions {
                name: name.map(Into::into),
                ..Default::default()
            });
            let body = ContainerCreateBody {
                // These ports will be externally accessible, but they won't
                // be connected to ports on the host. We will figure out the
                // container's IP address and talk to it there.
                exposed_ports: Some(exposed_ports),
                env: Some(env),
                image: Some(image_name.into()),
                host_config: Some(HostConfig {
                    mounts: Some(vec![Mount {
                        target: Some("/test/bin/cascaded".into()),
                        source: Some(daemon_path.into()),
                        typ: Some(MountType::BIND),
                        read_only: Some(true),
                        ..Default::default()
                    }]),
                    // Use the custom system resolver.
                    dns: Some(strs!["127.0.0.1"]),
                    // TODO: These were copied from an old, hand-written
                    // `resolv.conf` file. Are they still needed?
                    dns_options: Some(strs!["edns0", "trust-ad"]),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let output = docker.create_container(options, body).await.unwrap();
            let ContainerCreateResponse { id, warnings } = output;
            for w in warnings {
                tracing::warn!(msg = w, "warning during creation");
            }

            // The container must be started before we can exec commands in
            // it. Starting causes an initial command to be executed; when the
            // command finishes, the container will be stopped again. We don't
            // want these semantics. As a workaround, the `Dockerfile` sets
            // the entrypoint to `sleep inf`.
            docker.start_container(&id, None).await.unwrap();

            let (details, resolver, parent, primary, secondary) = tokio::join!(
                docker.inspect_container(&id, None),
                super::UnboundResolver::start(&docker, &id),
                super::BindParent::start(&docker, &id),
                super::NsdPrimary::start(&docker, &id),
                super::NsdSecondary::start(&docker, &id),
            );

            let details = details.unwrap();

            // If `self.name` was empty, Docker will provide a name for us.
            // Read from its output even if `self.name` was not empty.
            let mut name = details.name.unwrap();
            // `name` might start with `/` because of a historical quirk in
            // the Docker API, see `ContainerInspectResponse`.
            if name.starts_with("/") {
                name.replace_range(..1, "");
            }

            // TODO: Use `details.created`?
            let start_time = SystemTime::now();

            // Determine IP addresses to reach the container so that we can
            // access its exposed ports to talk to running services.
            let networks = details.network_settings.unwrap().networks.unwrap();
            let networks = networks.into_iter().collect::<Vec<_>>();
            let [(_name, network)] = &*networks else {
                panic!("Container is attached to more than one network")
            };
            let ipv4_addr = network
                .ip_address
                .as_ref()
                .unwrap()
                .parse::<Ipv4Addr>()
                .unwrap();
            let ipv6_addr = network
                .global_ipv6_address
                .as_ref()
                .filter(|addr| !addr.is_empty())
                .map(|addr| addr.parse::<Ipv6Addr>().unwrap());

            tracing::debug!(id, name, "Started container");

            Container {
                docker,
                id: id.into(),
                name: name.into(),
                ipv4_addr,
                ipv6_addr,
                start_time,
                resolver,
                parent,
                primary,
                secondary,
                dropped: false,
            }
        }
        .instrument(span)
    }
}

//----------- Container --------------------------------------------------------

/// A Docker container prepared for tests.
pub struct Container {
    /// A client for controlling Docker.
    pub docker: Arc<bollard::Docker>,

    /// The ID of the container.
    pub id: Box<str>,

    /// The name of the container.
    pub name: Box<str>,

    /// The IPv4 address of the container.
    pub ipv4_addr: Ipv4Addr,

    /// The IPv6 address of the container (if any).
    pub ipv6_addr: Option<Ipv6Addr>,

    /// When the container was started.
    pub start_time: SystemTime,

    /// The system resolver.
    #[expect(dead_code)]
    pub resolver: super::UnboundResolver,

    /// The parent name server.
    #[expect(dead_code)]
    pub parent: super::BindParent,

    /// The primary name server.
    #[expect(dead_code)]
    pub primary: super::NsdPrimary,

    /// The secondary name server.
    #[expect(dead_code)]
    pub secondary: super::NsdSecondary,

    /// Whether the container has been dropped manually.
    dropped: bool,
}

impl Container {
    /// The container's IP address.
    ///
    /// Returns an IPv6 address if possible, otherwise falls back to IPv4.
    pub const fn ip_addr(&self) -> IpAddr {
        match self.ipv6_addr {
            Some(addr) => IpAddr::V6(addr),
            None => IpAddr::V4(self.ipv4_addr),
        }
    }

    /// Query a DNS server.
    pub async fn dns_query(
        &self,
        port: ports::DnsPort,
        name: &str,
        rtype: Rtype,
        tsig_key: Option<Arc<tsig::Key>>,
    ) -> Result<Message<Bytes>, domain::net::client::request::Error> {
        let client = self.dns_client(port, tsig_key);

        let mut msg = MessageBuilder::new_vec();
        msg.header_mut().set_rd(false);
        msg.header_mut().set_ad(true);
        let mut msg = msg.question();
        msg.push((Name::vec_from_str(name).unwrap(), rtype))
            .unwrap();
        let req = RequestMessage::new(msg).unwrap();

        client.send_request(req).get_response().await
    }

    /// Build a simple DNS client for single-response requests.
    pub fn dns_client(
        &self,
        port: ports::DnsPort,
        tsig_key: Option<Arc<tsig::Key>>,
    ) -> Box<dyn SendRequest<RequestMessage<Vec<u8>>> + Send + Sync> {
        use domain::net::client;

        let addr = SocketAddr::new(self.ip_addr(), port.0);
        let udp_conn = client::protocol::UdpConnect::new(addr);
        let tcp_conn = client::protocol::TcpConnect::new(addr);
        if let Some(tsig_key) = tsig_key {
            let (client, transport) = client::dgram_stream::Connection::new(udp_conn, tcp_conn);
            tokio::task::spawn(transport.run());
            Box::new(client::tsig::Connection::new(tsig_key, client)) as _
        } else {
            let (client, transport) = client::dgram_stream::Connection::new(udp_conn, tcp_conn);
            tokio::task::spawn(transport.run());
            Box::new(client) as _
        }
    }

    /// Build a DNS client for XFR requests.
    #[allow(dead_code)]
    pub async fn dns_xfr_client(
        &self,
        port: ports::DnsPort,
        tsig_key: Option<Arc<tsig::Key>>,
    ) -> Box<dyn SendRequestMulti<RequestMessageMulti<Vec<u8>>> + Send + Sync> {
        use domain::net::client;

        let addr = SocketAddr::new(self.ip_addr(), port.0);
        let tcp_conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        if let Some(tsig_key) = tsig_key {
            let (client, transport) = client::stream::Connection::<
                RequestMessage<Vec<u8>>,
                client::tsig::RequestMessage<RequestMessageMulti<Vec<u8>>, Arc<tsig::Key>>,
            >::new(tcp_conn);
            tokio::task::spawn(transport.run());
            Box::new(client::tsig::Connection::new(tsig_key, client)) as _
        } else {
            let (client, transport) = client::stream::Connection::<
                RequestMessage<Vec<u8>>,
                RequestMessageMulti<Vec<u8>>,
            >::new(tcp_conn);
            tokio::task::spawn(transport.run());
            Box::new(client) as _
        }
    }

    /// Dump the contents of the container.
    ///
    /// The contents of the specified path in the container will be snapshotted
    /// as a tarball and saved to the user's current directory, with a unique
    /// filename.
    #[expect(dead_code)]
    pub async fn dump(&self, path: &str) -> Result<(), bollard::errors::Error> {
        Self::dump_impl(&self.docker, &self.id, &self.name, &self.start_time, path).await
    }

    #[tracing::instrument(level = "trace", name = "dump")]
    async fn dump_impl(
        docker: &Docker,
        id: &str,
        name: &str,
        start_time: &SystemTime,
        path: &str,
    ) -> Result<(), bollard::errors::Error> {
        tracing::trace!("Dumping contents of container");

        let options = Some(
            DownloadFromContainerOptionsBuilder::new()
                .path(path)
                .build(),
        );
        let stream = docker.download_from_container(id, options);

        let max_size_setting = super::CURRENT_CONFIG.get().unwrap().max_dump_size;
        let max_size = max_size_setting.unwrap_or(2 << 20);

        let mut file = tempfile::Builder::new().tempfile_in(".")?;
        let mut writer = BufWriter::new(&mut file);
        let mut size = 0usize;

        let mut stream = std::pin::pin!(stream);
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    tracing::error!("Error while fetching tarball: {error}");
                    return Err(error);
                }
            };

            let new_total = size + chunk.len();
            if new_total > max_size {
                tracing::error!("Truncating dump to {max_size}B");
                if max_size_setting.is_none() {
                    tracing::warn!("See the `max-dump-size` setting");
                }
                let trunc_len = max_size - size;
                writer.write_all(&chunk[..trunc_len])?;
                return Ok(());
            }

            tracing::trace!(size = chunk.len(), new_total, "Saving chunk");
            writer.write_all(&chunk)?;
            size = new_total;
        }

        writer.flush()?;
        std::mem::drop(writer);

        let offset = start_time.elapsed().unwrap().as_millis() as u32;
        let target = format!("./test-dump-{name}-{offset}");
        file.persist(&target).unwrap();

        tracing::debug!("Dumped {:?}", Path::new(&target).canonicalize().unwrap());

        Ok(())
    }

    /// Clean up the container.
    ///
    /// This is performed automatically (under certain conditions) on drop.
    #[expect(dead_code)]
    pub async fn cleanup(&mut self) {
        Self::cleanup_impl(&self.docker, &self.id).await;
        self.dropped = true;
    }

    #[tracing::instrument(level = "trace", name = "cleanup")]
    async fn cleanup_impl(docker: &Docker, id: &str) {
        tracing::trace!("Removing container");
        let result = docker
            .remove_container(
                id,
                Some(RemoveContainerOptionsBuilder::new().force(true).build()),
            )
            .await;
        if let Err(error) = result {
            tracing::error!("Failed to remove container: {error}");
        }

        tracing::debug!("Removed container");
    }
}

impl Drop for Container {
    /// Clean up the container on drop.
    ///
    /// The container is stopped, killed, and removed asynchronously.
    ///
    /// If a panic occurred and [`TestConfig::leave_containers_on_failure`] is
    /// set, the container is not removed.
    #[tracing::instrument(level = "trace")]
    fn drop(&mut self) {
        if self.dropped {
            // Nothing to do.
            return;
        }

        let mut dump = false;
        let mut cleanup = true;

        if std::thread::panicking() {
            // A failure has occurred. Dump the container data out for
            // inspection, and determine whether to remove it.
            dump = true;
            let config = super::CURRENT_CONFIG.get().unwrap();
            match config.leave_containers_on_failure {
                Some(true) => {
                    tracing::info!(id = %self.id, addr = %self.ip_addr(), "Leaving container");
                    cleanup = false;
                }
                Some(false) => {}
                None => {
                    tracing::warn!("Cleaning up container, see `leave-containers-on-failure`");
                    return;
                }
            }
        }

        let drop_permit = super::ONGOING_ASYNC_DROPS.try_acquire().unwrap();
        let docker = self.docker.clone();
        let id = self.id.clone();
        let name = self.name.clone();
        let start_time = self.start_time;
        tokio::spawn(async move {
            if dump {
                let _ = Self::dump_impl(&docker, &id, &name, &start_time, "/test").await;
            }
            if cleanup {
                Self::cleanup_impl(&docker, &id).await;
            }
            std::mem::drop(drop_permit);
        });
    }
}

impl fmt::Debug for Container {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

impl fmt::Display for Container {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}
