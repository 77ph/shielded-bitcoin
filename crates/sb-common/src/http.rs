//! The few lines of HTTP/1.1 the relayer and the indexer API need: one
//! request per connection, JSON in and out.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// Largest request body accepted (an envelope is 700 bytes = 1400 hex).
const MAX_BODY: usize = 16 * 1024;
/// Longest request or header line, and how many headers a request may carry.
const MAX_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 64;
/// How long a client has to send its whole request, and how long the
/// answer may take to be taken.
const READ_DEADLINE: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);
/// Requests being read or answered at once; beyond it a connection is
/// closed unanswered.
const MAX_IN_FLIGHT: usize = 256;

/// Request line, path and body of one HTTP/1.1 request, read within
/// [`READ_DEADLINE`] in all: a client that trickles bytes, or sends
/// headers without end, is cut off rather than holding the server.
pub fn read_request(conn: &TcpStream) -> Result<(String, String, Vec<u8>)> {
    let deadline = Instant::now() + READ_DEADLINE;
    let mut reader = BufReader::new(conn.try_clone()?);
    let mut line = String::new();
    read_line_until(conn, &mut reader, &mut line, deadline)?;
    if line.is_empty() {
        bail!("empty request");
    }
    let (method, path) = request_line(&line)?;
    let mut content_length = 0usize;
    let mut headers = 0usize;
    loop {
        let mut h = String::new();
        read_line_until(conn, &mut reader, &mut h, deadline)?;
        if h.is_empty() {
            bail!("truncated headers");
        }
        if h.trim().is_empty() {
            break;
        }
        headers += 1;
        if headers > MAX_HEADERS {
            bail!("too many headers");
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().context("content-length")?;
        }
    }
    if content_length > MAX_BODY {
        bail!("body too large");
    }
    let mut body = vec![0u8; content_length];
    let mut got = 0;
    while got < content_length {
        remaining(conn, deadline)?;
        let n = reader.read(&mut body[got..]).context("body")?;
        if n == 0 {
            bail!("body: truncated");
        }
        got += n;
    }
    Ok((method, path, body))
}

/// [`read_request`] over any reader (the fuzz target feeds it bytes): the
/// same lines and limits, without a clock.
pub fn read_request_from<R: BufRead>(mut reader: R) -> Result<(String, String, Vec<u8>)> {
    let mut line = String::new();
    if reader.by_ref().take(MAX_LINE as u64).read_line(&mut line)? == 0 {
        bail!("empty request");
    }
    if !line.ends_with('\n') && line.len() >= MAX_LINE {
        bail!("request line too long");
    }
    let (method, path) = request_line(&line)?;
    let mut content_length = 0usize;
    let mut headers = 0usize;
    loop {
        let mut h = String::new();
        if reader.by_ref().take(MAX_LINE as u64).read_line(&mut h)? == 0 {
            bail!("truncated headers");
        }
        if !h.ends_with('\n') && h.len() >= MAX_LINE {
            bail!("header too long");
        }
        if h.trim().is_empty() {
            break;
        }
        headers += 1;
        if headers > MAX_HEADERS {
            bail!("too many headers");
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().context("content-length")?;
        }
    }
    if content_length > MAX_BODY {
        bail!("body too large");
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).context("body")?;
    Ok((method, path, body))
}

fn request_line(line: &str) -> Result<(String, String)> {
    let mut parts = line.split_whitespace();
    let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
        bail!("malformed request line");
    };
    Ok((method.to_string(), path.to_string()))
}

/// The time left until `deadline` set as the socket's read timeout.
fn remaining(conn: &TcpStream, deadline: Instant) -> Result<()> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        bail!("request too slow");
    }
    conn.set_read_timeout(Some(left))?;
    Ok(())
}

/// One line of at most [`MAX_LINE`] bytes (the newline included), by
/// `deadline`; an empty `line` means the peer closed.
fn read_line_until(
    conn: &TcpStream,
    reader: &mut BufReader<TcpStream>,
    line: &mut String,
    deadline: Instant,
) -> Result<()> {
    let mut bytes = Vec::new();
    loop {
        remaining(conn, deadline)?;
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        let (chunk, done) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (buf.len(), false),
        };
        if bytes.len() + chunk > MAX_LINE {
            bail!("line too long");
        }
        bytes.extend_from_slice(&buf[..chunk]);
        reader.consume(chunk);
        if done {
            break;
        }
    }
    line.push_str(&String::from_utf8_lossy(&bytes));
    Ok(())
}

/// A request read off a connection, or why it was refused.
pub type Incoming = (TcpStream, IpAddr, Result<(String, String, Vec<u8>)>);

/// Serve `listener`: every connection's request is read by its own thread
/// under [`READ_DEADLINE`] (a slow or silent client holds that thread, not
/// the server), `handle` runs on the calling thread one request at a time,
/// and the answer is written by a thread with [`WRITE_TIMEOUT`] (a client
/// that does not read holds that thread alone). At most [`MAX_IN_FLIGHT`]
/// connections are in hand at once; further ones are closed unanswered.
/// Returns after `max_requests` answers (`None`: never), or when `stop`
/// says so after an answer.
pub fn serve<H, S>(
    listener: TcpListener,
    max_requests: Option<u32>,
    mut stop: S,
    mut handle: H,
) -> Result<()>
where
    H: FnMut(&str, &str, &[u8], IpAddr) -> (u16, Value),
    S: FnMut() -> bool,
{
    let (tx, rx) = mpsc::channel::<Incoming>();
    let in_flight = Arc::new(AtomicUsize::new(0));
    let counter = in_flight.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else {
                continue;
            };
            let Ok(peer) = conn.peer_addr() else {
                continue;
            };
            if counter.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
                counter.fetch_sub(1, Ordering::SeqCst);
                drop(conn);
                continue;
            }
            let tx = tx.clone();
            let counter = counter.clone();
            std::thread::spawn(move || {
                let req = read_request(&conn);
                if tx.send((conn, peer.ip(), req)).is_err() {
                    counter.fetch_sub(1, Ordering::SeqCst);
                }
            });
        }
    });
    let mut served = 0u32;
    let mut writers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    while max_requests.is_none_or(|m| served < m) {
        let Ok((conn, ip, req)) = rx.recv() else {
            break;
        };
        let (status, body) = match req {
            Ok((method, path, body)) => handle(&method, &path, &body, ip),
            Err(e) => (400, serde_json::json!({"error": e.to_string()})),
        };
        log::info!("{ip}: {status}");
        let counter = in_flight.clone();
        writers.retain(|w| !w.is_finished());
        writers.push(std::thread::spawn(move || {
            let _ = conn.set_write_timeout(Some(WRITE_TIMEOUT));
            respond(conn, status, &body);
            counter.fetch_sub(1, Ordering::SeqCst);
        }));
        served += 1;
        if stop() {
            break;
        }
    }
    // the answers in flight are written (or time out) before the caller
    // may exit
    for w in writers {
        let _ = w.join();
    }
    Ok(())
}

/// `POST` a JSON body to `url` and parse the JSON answer. A refusal (non-2xx)
/// becomes `<service> refused (<code>): <its error field>`, a transport
/// failure `<service> unreachable: …`.
pub fn post_json(url: &str, body: &impl serde::Serialize, service: &str) -> Result<Value> {
    let resp = crate::net::agent()
        .post(url)
        .timeout(std::time::Duration::from_secs(120))
        .send_json(body)
        .map_err(|e| refusal(e, service))?;
    crate::net::json(resp).with_context(|| format!("{service} response"))
}

/// `GET` a JSON document from `url`, with the same error mapping.
pub fn get_json(url: &str, service: &str) -> Result<Value> {
    let resp = crate::net::agent()
        .get(url)
        .timeout(std::time::Duration::from_secs(30))
        .call()
        .map_err(|e| refusal(e, service))?;
    crate::net::json(resp).with_context(|| format!("{service} response"))
}

fn refusal(e: ureq::Error, service: &str) -> anyhow::Error {
    match e {
        ureq::Error::Status(code, r) => {
            let text = r.into_string().unwrap_or_default();
            let msg = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v["error"].as_str().map(str::to_string))
                .unwrap_or(text);
            anyhow::anyhow!("{service} refused ({code}): {}", msg.trim())
        }
        other => anyhow::anyhow!("{service} unreachable: {other}{}", crate::net::route()),
    }
}

pub fn respond(mut conn: TcpStream, status: u16, body: &Value) {
    let out = serde_json::to_vec(body).unwrap_or_default();
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        match status {
            200 => "OK",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "Bad Request",
        },
        out.len()
    );
    let _ = conn.write_all(header.as_bytes());
    let _ = conn.write_all(&out);
    let _ = conn.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Read;
    use std::net::TcpListener;
    use std::time::Duration;

    /// A request that never completes its headers is answered 400 and does
    /// not stall the server; so is an oversized body.
    #[test]
    fn malformed_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut replies = Vec::new();
            for _ in 0..4 {
                let (conn, _) = listener.accept().unwrap();
                let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
                let (status, body) = match read_request(&conn) {
                    Ok((m, p, b)) => (200, json!({"m": m, "p": p, "n": b.len()})),
                    Err(e) => (400, json!({"error": e.to_string()})),
                };
                replies.push(status);
                respond(conn, status, &body);
            }
            replies
        });
        let send = |raw: &str| -> String {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(raw.as_bytes()).unwrap();
            let _ = c.shutdown(std::net::Shutdown::Write);
            let mut s = String::new();
            c.read_to_string(&mut s).unwrap();
            s
        };
        assert!(send("").contains("400"));
        assert!(send("GARBAGE\r\n").contains("400"));
        assert!(
            send("POST /relay HTTP/1.1\r\nContent-Length: 999999\r\n\r\n").contains("too large")
        );
        let ok = send("POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc");
        assert!(ok.contains("200") && ok.contains("\"n\":3"), "{ok}");
        assert_eq!(t.join().unwrap(), vec![400, 400, 400, 200]);
    }

    /// A connection that says nothing, a request line past the cap and a
    /// header storm are each refused or left to their own thread; a good
    /// request behind them is answered.
    #[test]
    fn a_stalled_or_abusive_connection_does_not_hold_the_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            serve(
                listener,
                Some(3),
                || false,
                |method, path, body, _| {
                    (
                        200,
                        serde_json::json!({"m": method, "p": path, "n": body.len()}),
                    )
                },
            )
        });
        let silent = TcpStream::connect(addr).unwrap();
        let send = |raw: &[u8]| -> String {
            let mut c = TcpStream::connect(addr).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            c.write_all(raw).unwrap();
            let _ = c.shutdown(std::net::Shutdown::Write);
            let mut s = String::new();
            let _ = c.read_to_string(&mut s);
            s
        };
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_LINE + 1000));
        assert!(send(long.as_bytes()).contains("too long"));
        let mut storm = String::from("GET /x HTTP/1.1\r\n");
        for i in 0..MAX_HEADERS + 5 {
            storm.push_str(&format!("X-{i}: y\r\n"));
        }
        storm.push_str("\r\n");
        assert!(send(storm.as_bytes()).contains("too many headers"));
        let ok = send(b"POST /y HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi");
        assert!(ok.contains("200") && ok.contains("\"n\":2"), "{ok}");
        drop(silent);
        t.join().unwrap().unwrap();
    }
}
