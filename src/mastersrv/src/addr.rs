use arrayvec::ArrayString;
use std::fmt::Write;
use std::fmt;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use url::Url;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Protocol {
    V5,
    V6,
    V7,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Addr {
    // `ip`, `port` come before `protocol` so that the order groups addresses
    // with the same IP addresses together.
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

pub struct UnknownProtocol;

impl FromStr for Protocol {
    type Err = UnknownProtocol;
    fn from_str(s: &str) -> Result<Protocol, UnknownProtocol> {
        use self::Protocol::*;
        Ok(match s {
            "tw-0.5+udp" => V5,
            "tw-0.6+udp" => V6,
            "tw-0.7+udp" => V7,
            _ => return Err(UnknownProtocol),
        })
    }
}

impl serde::Serialize for Protocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

struct ProtocolVisitor;

impl<'de> serde::de::Visitor<'de> for ProtocolVisitor {
    type Value = Protocol;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("one of \"tw-0.5+udp\", \"tw-0.6+udp\" and \"tw-0.7+udp\"")
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Protocol, E> {
        let invalid_value = || E::invalid_value(serde::de::Unexpected::Str(v), &self);
        Ok(Protocol::from_str(v).map_err(|_| invalid_value())?)
    }
}

impl<'de> serde::Deserialize<'de> for Protocol {
    fn deserialize<D>(deserializer: D) -> Result<Protocol, D::Error>
        where D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_str(ProtocolVisitor)
    }
}


impl Protocol {
    fn as_str(self) -> &'static str {
        use self::Protocol::*;
        match self {
            V5 => "tw-0.5+udp",
            V6 => "tw-0.6+udp",
            V7 => "tw-0.7+udp",
        }
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf: ArrayString<128> = ArrayString::new();
        write!(&mut buf, "{}://{}", self.protocol, SocketAddr::new(self.ip, self.port)).unwrap();
        buf.fmt(f)
    }
}

impl serde::Serialize for Addr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer,
    {
        let mut buf: ArrayString<128> = ArrayString::new();
        write!(&mut buf, "{}", self).unwrap();
        serializer.serialize_str(&buf)
    }
}

struct AddrVisitor;

impl<'de> serde::de::Visitor<'de> for AddrVisitor {
    type Value = Addr;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a URL like tw-0.6+udp://127.0.0.1:8303")
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Addr, E> {
        use url::Host::*;
        let invalid_value = || E::invalid_value(serde::de::Unexpected::Str(v), &self);
        let url = Url::parse(v).map_err(|_| invalid_value())?;
        let protocol: Protocol = url.scheme().parse().map_err(|_| invalid_value())?;
        let ip = match url.host() {
            Some(Domain(_)) => return Err(invalid_value()),
            Some(Ipv4(ip)) => ip.into(),
            Some(Ipv6(ip)) => ip.into(),
            None => return Err(invalid_value()),
        };
        let port = url.port().ok_or_else(invalid_value)?;
        Ok(Addr {
            ip,
            port,
            protocol,
        })
    }
}

impl<'de> serde::Deserialize<'de> for Addr {
    fn deserialize<D>(deserializer: D) -> Result<Addr, D::Error>
        where D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_str(AddrVisitor)
    }
}

