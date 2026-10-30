//! The few lines of HTTP/1.1 the relayer and the indexer API need: one
//! request per connection, JSON in and out.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// Largest request body accepted (an envelope is 700 bytes = 1400 hex).
const MAX_BODY: usize = 16 * 1024;

/// Request line, path and body of one HTTP/1.1 request.
pub fn read_request(conn: &TcpStream) -> Result<(String, String, Vec<u8>)> {
    let mut reader = BufReader::new(conn.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        bail!("empty request");
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
        bail!("malformed request line");
    };
    let (method, path) = (method.to_string(), path.to_string());
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            bail!("truncated headers");
        }
        if h.trim().is_empty() {
            break;
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

/// `POST` a JSON body to `url` and parse the JSON answer. A refusal (non-2xx)
/// becomes `<service> refused (<code>): <its error field>`, a transport
/// failure `<service> unreachable: …`.
pub fn post_json(url: &str, body: &impl serde::Serialize, service: &str) -> Result<Value> {
    let resp = crate::net::agent()
        .post(url)
        .timeout(std::time::Duration::from_secs(120))
        .send_json(body)
        .map_err(|e| refusal(e, service))?;
    resp.into_json()
        .with_context(|| format!("{service} response"))
}

/// `GET` a JSON document from `url`, with the same error mapping.
pub fn get_json(url: &str, service: &str) -> Result<Value> {
    let resp = crate::net::agent()
        .get(url)
        .timeout(std::time::Duration::from_secs(30))
        .call()
        .map_err(|e| refusal(e, service))?;
    resp.into_json()
        .with_context(|| format!("{service} response"))
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
}
