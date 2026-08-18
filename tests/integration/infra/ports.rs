//! Defining and communicating Internet ports.

use std::fmt;

//----------- Hard-coded port numbers ------------------------------------------

/// The system resolver.
pub const RESOLVER: DnsPort = DnsPort(53);

/// The parent name server.
pub const PARENT: DnsPort = DnsPort(1053);

/// The primary name server.
pub const PRIMARY: DnsPort = DnsPort(1055);

/// The secondary name server.
pub const SECONDARY: DnsPort = DnsPort(1054);

/// The Cascade remote control server.
pub const REMOTE_CONTROL: HttpPort = HttpPort(4539);

/// The Cascade loaded review server.
pub const LOADED_REVIEW: DnsPort = DnsPort(4540);

/// The Cascade signed review server.
pub const SIGNED_REVIEW: DnsPort = DnsPort(4541);

/// The Cascade publication server.
pub const PUBLICATION: DnsPort = DnsPort(4542);

/// All known ports.
pub fn all() -> impl IntoIterator<Item = InPort> {
    [
        RESOLVER,
        PARENT,
        PRIMARY,
        SECONDARY,
        LOADED_REVIEW,
        SIGNED_REVIEW,
        PUBLICATION,
    ]
    .into_iter()
    .flatten()
    .chain(REMOTE_CONTROL)
}

//----------- Typed ports ------------------------------------------------------

/// A DNS (TCP + UDP) port.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DnsPort(pub u16);

impl IntoIterator for DnsPort {
    type Item = InPort;
    type IntoIter = std::array::IntoIter<InPort, 2>;

    fn into_iter(self) -> Self::IntoIter {
        [InPort::Tcp(self.0), InPort::Udp(self.0)].into_iter()
    }
}

impl fmt::Display for DnsPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An HTTP (TCP) port.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpPort(pub u16);

impl IntoIterator for HttpPort {
    type Item = InPort;
    type IntoIter = std::iter::Once<InPort>;

    fn into_iter(self) -> Self::IntoIter {
        std::iter::once(InPort::Tcp(self.0))
    }
}

impl fmt::Display for HttpPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A generic (TCP or UDP) Internet port.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InPort {
    /// Over TCP.
    Tcp(u16),
    /// Over UDP.
    Udp(u16),
}

impl IntoIterator for InPort {
    type Item = InPort;
    type IntoIter = std::iter::Once<InPort>;

    fn into_iter(self) -> Self::IntoIter {
        std::iter::once(self)
    }
}

impl fmt::Display for InPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InPort::Tcp(p) => write!(f, "{p}/tcp"),
            InPort::Udp(p) => write!(f, "{p}/udp"),
        }
    }
}

/// A TCP port.
#[expect(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcpPort(pub u16);

impl IntoIterator for TcpPort {
    type Item = InPort;
    type IntoIter = std::iter::Once<InPort>;

    fn into_iter(self) -> Self::IntoIter {
        std::iter::once(InPort::Tcp(self.0))
    }
}

impl fmt::Display for TcpPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A UDP port.
#[expect(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UdpPort(pub u16);

impl IntoIterator for UdpPort {
    type Item = InPort;
    type IntoIter = std::iter::Once<InPort>;

    fn into_iter(self) -> Self::IntoIter {
        std::iter::once(InPort::Udp(self.0))
    }
}

impl fmt::Display for UdpPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
