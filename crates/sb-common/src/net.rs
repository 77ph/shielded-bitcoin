//! Outbound connections (`docs/PUBLICATION.md` §2.1): one process-wide
//! proxy setting that every HTTP client and raw TCP connection of this
//! program honours. With a proxy set, nothing goes out directly: a
//! connection that cannot be made through it fails.
//!
//! The proxy is SOCKS5 (`socks5://host:port`), Tor's and `ssh -D`'s
//! dialect. Target host names are sent to the proxy and resolved there,
//! so there is no local DNS lookup to observe.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::OnceLock;
use std::time::Duration;

use crate::chain::ChainError;

static PROXY: OnceLock<Option<Proxy>> = OnceLock::new();
static AGENT: OnceLock<ureq::Agent> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proxy {
    pub host: String,
    pub port: u16,
}

impl Proxy {
    /// `socks5://host:port` (`socks5h://` is accepted as the same thing:
    /// names are always resolved by the proxy).
    pub fn parse(url: &str) -> Result<Self, ChainError> {
        let rest = url
            .strip_prefix("socks5://")
            .or_else(|| url.strip_prefix("socks5h://"))
            .ok_or_else(|| {
                ChainError::Rpc(format!(
                    "proxy {url:?}: only socks5://host:port is supported"
                ))
            })?;
        let rest = rest.trim_end_matches('/');
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| ChainError::Rpc(format!("proxy {url:?}: host:port expected")))?;
        let port: u16 = port
            .parse()
            .map_err(|_| ChainError::Rpc(format!("proxy {url:?}: bad port")))?;
        if host.is_empty() {
            return Err(ChainError::Rpc(format!("proxy {url:?}: empty host")));
        }
        Ok(Proxy {
            host: host.to_string(),
            port,
        })
    }

    fn url(&self) -> String {
        format!("socks5://{}:{}", self.host, self.port)
    }
}

/// Set the proxy once, at startup; a second call is ignored (the first
/// setting wins) so that no code path can switch to direct connections.
pub fn set_proxy(url: Option<&str>) -> Result<(), ChainError> {
    let p = match url {
        Some(u) => Some(Proxy::parse(u)?),
        None => None,
    };
    let _ = PROXY.set(p);
    Ok(())
}

pub fn proxy() -> Option<&'static Proxy> {
    PROXY.get().and_then(|p| p.as_ref())
}

/// `" (via socks5 proxy host:port)"` when a proxy is set, else empty: for
/// error messages, so that a failure names the route it took.
pub fn route() -> String {
    match proxy() {
        Some(p) => format!(" (via socks5 proxy {}:{})", p.host, p.port),
        None => String::new(),
    }
}

/// The HTTP client every request goes through.
pub fn agent() -> &'static ureq::Agent {
    AGENT.get_or_init(|| {
        let mut b = ureq::AgentBuilder::new();
        if let Some(p) = proxy() {
            b = b.proxy(
                ureq::Proxy::new(p.url()).expect("a parsed socks5 proxy is a valid ureq proxy"),
            );
        }
        b.build()
    })
}

/// A TCP connection to `host:port`, through the proxy when one is set
/// (SOCKS5 CONNECT with the name, not an address), else to the first
/// reachable address of the host.
pub fn connect_tcp(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, ChainError> {
    match proxy() {
        Some(p) => socks5_connect(p, host, port, timeout),
        None => connect_direct(host, port, timeout),
    }
}

fn connect_direct(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, ChainError> {
    let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(ChainError::Rpc(format!("cannot resolve {host}")));
    }
    let mut last = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(tcp) => return Ok(tcp),
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("at least one address").into())
}

fn socks_err(what: &str) -> ChainError {
    ChainError::Rpc(format!("socks5 proxy: {what}"))
}

/// RFC 1928: no authentication, CONNECT to a domain name.
fn socks5_connect(
    p: &Proxy,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, ChainError> {
    if host.len() > 255 {
        return Err(socks_err("host name too long"));
    }
    let mut s = connect_direct(&p.host, p.port, timeout)
        .map_err(|e| ChainError::Rpc(format!("socks5 proxy {}:{}: {e}", p.host, p.port)))?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply)?;
    if reply != [0x05, 0x00] {
        return Err(socks_err("no-authentication method refused"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[0] != 0x05 {
        return Err(socks_err("bad reply version"));
    }
    if head[1] != 0x00 {
        let why = match head[1] {
            0x01 => "general failure",
            0x02 => "connection not allowed",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(socks_err(&format!("CONNECT {host}:{port} failed: {why}")));
    }
    // the bound address, which we do not need: skip it
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize
        }
        _ => return Err(socks_err("bad address type in reply")),
    };
    let mut skip = vec![0u8; addr_len + 2];
    s.read_exact(&mut skip)?;
    s.set_read_timeout(None)?;
    s.set_write_timeout(None)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_urls() {
        assert_eq!(
            Proxy::parse("socks5://127.0.0.1:9050").unwrap(),
            Proxy {
                host: "127.0.0.1".into(),
                port: 9050
            }
        );
        assert_eq!(
            Proxy::parse("socks5h://tor:9150/").unwrap(),
            Proxy {
                host: "tor".into(),
                port: 9150
            }
        );
        for bad in ["http://x:1", "socks5://x", "socks5://:1", "socks5://x:y"] {
            assert!(Proxy::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn socks5_connect_reaches_the_target_by_name_and_reports_refusals() {
        use std::net::TcpListener;
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = target.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut c, _) = target.accept().unwrap();
            let mut b = [0u8; 5];
            c.read_exact(&mut b).unwrap();
            c.write_all(&b).unwrap();
        });
        let socks = crate::chain::fake::FakeSocks::start();
        let p = Proxy {
            host: socks.addr.ip().to_string(),
            port: socks.addr.port(),
        };
        let mut s = socks5_connect(&p, "localhost", port, Duration::from_secs(5)).unwrap();
        s.write_all(b"hello").unwrap();
        let mut back = [0u8; 5];
        s.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        assert_eq!(
            socks.targets.lock().unwrap().as_slice(),
            [format!("localhost:{port}")]
        );
        // a target the proxy cannot reach is an error, not a direct attempt
        let e = socks5_connect(&p, "127.0.0.1", 1, Duration::from_secs(5)).unwrap_err();
        assert!(e.to_string().contains("CONNECT"), "{e}");
        // a proxy that is not there
        let gone = Proxy {
            host: "127.0.0.1".into(),
            port: 1,
        };
        let e = socks5_connect(&gone, "localhost", port, Duration::from_secs(1)).unwrap_err();
        assert!(e.to_string().contains("socks5 proxy"), "{e}");
    }

    #[test]
    fn direct_connection_errors_name_the_host() {
        let e = connect_direct("127.0.0.1", 1, Duration::from_secs(1)).unwrap_err();
        assert!(
            e.to_string().contains("refused") || e.to_string().contains("os error"),
            "{e}"
        );
    }
}
