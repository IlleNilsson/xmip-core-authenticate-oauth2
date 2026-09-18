//! The introspection call: RFC 7662 section 2, asked of an authorization
//! server the configuration names.
//!
//! [`Introspection`] is the seam: given a token it answers the JSON the
//! server said. [`Http`] is the implementation this crate carries — one
//! `POST` of `token=<token>` as a form over plain HTTP/1.1 on a TCP
//! connection it opens and closes, with the client credentials RFC 7662
//! section 2.1 requires as HTTP Basic. It speaks no TLS: an `https` endpoint
//! is refused when it is configured, with the reason, and a host that
//! terminates TLS in front of this node implements [`Introspection`] over
//! its own client instead.
//!
//! Offline is the default (ADR-0045). [`Http`] opens a connection only where
//! the endpoint is loopback — an address in `127.0.0.0/8`, `::1`, or the
//! name `localhost` resolving to one — or where the configuration has said
//! the node is [`online`](Http::online). Otherwise the call is refused and
//! the refusal says which of the two would change it.

use authenticate::AuthenticateError;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Asks an authorization server about one token.
pub trait Introspection: Send + Sync {
    /// The JSON body of the server's introspection response.
    ///
    /// # Errors
    ///
    /// Where the server cannot be asked or does not answer `200` with a
    /// body; the message says which.
    fn introspect(&self, token: &str) -> Result<String, AuthenticateError>;
}

/// The introspection endpoint over plain HTTP/1.1.
#[derive(Clone)]
pub struct Http {
    host: String,
    port: u16,
    path: String,
    client: Option<(String, String)>,
    online: bool,
    timeout: Duration,
}

// The client secret does not belong in a log line; the client id says whose
// it is.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for Http {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("path", &self.path)
            .field("client", &self.client.as_ref().map(|(id, _)| id))
            .field("online", &self.online)
            .finish()
    }
}

impl Http {
    /// The endpoint at `url`: `http://host[:port]/path`. The node is taken
    /// to be offline, no client credentials, five seconds to answer.
    ///
    /// # Errors
    ///
    /// Where the URL is `https` — this client speaks no TLS — or is not an
    /// `http` URL with a host.
    pub fn at(url: &str) -> Result<Self, AuthenticateError> {
        if url.starts_with("https://") {
            return Err(AuthenticateError::new(format!(
                "the introspection endpoint '{url}' is https and this client speaks plain \
                 HTTP only: give the verifier an Introspection over the host's TLS client"
            )));
        }
        let rest = url.strip_prefix("http://").ok_or_else(|| {
            AuthenticateError::new(format!(
                "the introspection endpoint '{url}' is not an http URL"
            ))
        })?;
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !port.contains(']') => (
                host,
                port.parse::<u16>().map_err(|_| {
                    AuthenticateError::new(format!(
                        "the introspection endpoint '{url}' has a port that is not a number"
                    ))
                })?,
            ),
            _ => (authority, 80),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return Err(AuthenticateError::new(format!(
                "the introspection endpoint '{url}' names no host"
            )));
        }
        Ok(Self {
            host: host.to_string(),
            port,
            path: path.to_string(),
            client: None,
            online: false,
            timeout: Duration::from_secs(5),
        })
    }

    /// The configuration says this node may reach beyond itself.
    #[must_use]
    pub const fn online(mut self) -> Self {
        self.online = true;
        self
    }

    /// Authenticate to the endpoint as this client, with HTTP Basic.
    #[must_use]
    pub fn as_client(mut self, id: impl Into<String>, secret: impl Into<String>) -> Self {
        self.client = Some((id.into(), secret.into()));
        self
    }

    /// How long the server has to accept the connection and to answer.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The addresses this node may connect to, given what it may reach.
    fn reachable(&self) -> Result<Vec<SocketAddr>, AuthenticateError> {
        let literal = self.host.parse::<IpAddr>().ok();
        let names_loopback = literal.is_some_and(|address| address.is_loopback())
            || self.host.eq_ignore_ascii_case("localhost");
        if !self.online && !names_loopback {
            return Err(AuthenticateError::new(format!(
                "the node is offline (ADR-0045) and the introspection endpoint '{}' is not \
                 loopback: configure the node online, or an endpoint on this host",
                self.host
            )));
        }
        let resolved: Vec<SocketAddr> = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|failure| {
                AuthenticateError::new(format!(
                    "the introspection endpoint '{}' does not resolve: {failure}",
                    self.host
                ))
            })?
            .filter(|address| self.online || address.ip().is_loopback())
            .collect();
        if resolved.is_empty() {
            return Err(AuthenticateError::new(format!(
                "the node is offline (ADR-0045) and '{}' resolves to no loopback address",
                self.host
            )));
        }
        Ok(resolved)
    }

    fn request(&self, token: &str) -> String {
        let body = format!("token={}&token_type_hint=access_token", form_encoded(token));
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let authorization = self
            .client
            .as_ref()
            .map_or_else(String::new, |(id, secret)| {
                let credential = STANDARD.encode(format!("{id}:{secret}"));
                format!("Authorization: Basic {credential}\r\n")
            });
        format!(
            "POST {} HTTP/1.1\r\nHost: {host}:{}\r\nAccept: application/json\r\n\
             Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
             Connection: close\r\n{authorization}\r\n{body}",
            self.path,
            self.port,
            body.len()
        )
    }
}

impl Introspection for Http {
    fn introspect(&self, token: &str) -> Result<String, AuthenticateError> {
        let unreachable = |failure: std::io::Error| {
            AuthenticateError::new(format!(
                "the introspection endpoint {}:{} did not answer: {failure}",
                self.host, self.port
            ))
        };
        let addresses = self.reachable()?;
        let mut stream = addresses
            .iter()
            .find_map(|address| TcpStream::connect_timeout(address, self.timeout).ok())
            .ok_or_else(|| {
                AuthenticateError::new(format!(
                    "the introspection endpoint {}:{} refused the connection",
                    self.host, self.port
                ))
            })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(unreachable)?;
        stream
            .write_all(self.request(token).as_bytes())
            .map_err(unreachable)?;

        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).map_err(unreachable)?;
        response_body(&String::from_utf8_lossy(&answer))
    }
}

/// The body of a `200`, de-chunked where the server chunked it.
fn response_body(answer: &str) -> Result<String, AuthenticateError> {
    let (head, body) = answer.split_once("\r\n\r\n").ok_or_else(|| {
        AuthenticateError::new("the introspection endpoint's answer is not an HTTP response")
    })?;
    let mut lines = head.lines();
    let status = lines.next().unwrap_or_default();
    let code = status.split_whitespace().nth(1).unwrap_or_default();
    if code != "200" {
        return Err(AuthenticateError::new(match code {
            "401" | "403" => format!(
                "the authorization server refused this node's client credentials: '{status}'"
            ),
            _ => format!("the introspection endpoint answered '{status}' and not 200"),
        }));
    }
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    if chunked {
        unchunked(body)
    } else {
        Ok(body.to_string())
    }
}

fn unchunked(mut body: &str) -> Result<String, AuthenticateError> {
    let broken = || AuthenticateError::new("the introspection endpoint's chunked body is broken");
    let mut whole = String::new();
    loop {
        let (size, rest) = body.split_once("\r\n").ok_or_else(broken)?;
        let size = size.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| broken())?;
        if size == 0 {
            return Ok(whole);
        }
        whole.push_str(rest.get(..size).ok_or_else(broken)?);
        body = rest
            .get(size..)
            .and_then(|after| after.strip_prefix("\r\n"))
            .ok_or_else(broken)?;
    }
}

/// `application/x-www-form-urlencoded`: everything but the unreserved set is
/// a percent escape.
fn form_encoded(text: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_https_endpoint_is_refused_when_it_is_configured_and_says_what_to_do() {
        let failure = Http::at("https://as.example/introspect").expect_err("refused");

        assert!(failure.message.contains("plain HTTP only"));
    }

    #[test]
    fn an_offline_node_refuses_an_endpoint_beyond_itself_and_says_why() {
        let endpoint = Http::at("http://as.example:8080/introspect").expect("a URL");

        let failure = endpoint.introspect("token").expect_err("refused");

        assert!(failure.message.contains("offline (ADR-0045)"));
        assert!(failure.message.contains("as.example"));
    }

    #[test]
    fn a_url_is_read_into_host_port_and_path() {
        let endpoint = Http::at("http://[::1]:9000/oauth/introspect").expect("a URL");
        let plain = Http::at("http://localhost").expect("a URL");

        assert_eq!(
            (
                endpoint.host.as_str(),
                endpoint.port,
                endpoint.path.as_str()
            ),
            ("::1", 9000, "/oauth/introspect")
        );
        assert_eq!((plain.port, plain.path.as_str()), (80, "/"));
    }

    #[test]
    fn a_chunked_body_is_put_back_together_and_a_401_names_the_credentials() {
        let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                       8\r\n{\"active\r\n7\r\n\":true}\r\n0\r\n\r\n";
        let denied = "HTTP/1.1 401 Unauthorized\r\n\r\n";

        assert_eq!(response_body(chunked).expect("a body"), "{\"active\":true}");
        assert!(
            response_body(denied)
                .expect_err("refused")
                .message
                .contains("client credentials")
        );
    }

    #[test]
    fn a_token_is_form_encoded_so_its_punctuation_survives_the_post() {
        assert_eq!(form_encoded("a+b/c=d.e-f"), "a%2Bb%2Fc%3Dd.e-f");
    }
}
