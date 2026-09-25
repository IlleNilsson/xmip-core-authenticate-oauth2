//! The introspection call: RFC 7662 section 2, asked of an authorization
//! server the configuration names.
//!
//! [`Introspection`] is the seam: given a token it answers the JSON the
//! server said. [`Http`] is the implementation this crate carries — one
//! `POST` of `token=<token>` as a form over the estate's minimal HTTP/1.1
//! client, `net::http`, on a TCP connection it opens and closes, with the
//! client credentials RFC 7662 section 2.1 requires as HTTP Basic. It
//! speaks no TLS: an `https` endpoint is refused when it is configured,
//! with the reason, and a host that terminates TLS in front of this node
//! implements [`Introspection`] over its own client instead.
//!
//! Offline is the default (ADR-0045). [`Http`] opens a connection only where
//! the endpoint is loopback — an address in `127.0.0.0/8`, `::1`, or the
//! name `localhost` resolving to one — or where the configuration has said
//! the node is [`online`](Http::online). Otherwise the call is refused and
//! the refusal says which of the two would change it.

use authenticate::AuthenticateError;
use net::Endpoint;
use net::http::{self, Request};
use std::net::SocketAddr;
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
    endpoint: Endpoint,
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
            .field("endpoint", &self.endpoint)
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
    /// Where the URL is not an `http` URL with a host — an `https` one
    /// among them, since this client speaks no TLS: give the verifier an
    /// [`Introspection`] over the host's TLS client instead.
    pub fn at(url: &str) -> Result<Self, AuthenticateError> {
        let endpoint = Endpoint::parse(url)
            .and_then(Endpoint::plain)
            .map_err(|refused| {
                AuthenticateError::new(format!("the introspection endpoint {refused}"))
            })?;
        Ok(Self {
            endpoint,
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
        let host = self.endpoint.host();
        if !self.online && !self.endpoint.names_loopback() {
            return Err(AuthenticateError::new(format!(
                "the node is offline (ADR-0045) and the introspection endpoint '{host}' is not \
                 loopback: configure the node online, or an endpoint on this host"
            )));
        }
        let resolved: Vec<SocketAddr> = self
            .endpoint
            .resolve()
            .map_err(|failure| {
                AuthenticateError::new(format!("the introspection endpoint {failure}"))
            })?
            .into_iter()
            .filter(|address| self.online || address.ip().is_loopback())
            .collect();
        if resolved.is_empty() {
            return Err(AuthenticateError::new(format!(
                "the node is offline (ADR-0045) and '{host}' resolves to no loopback address"
            )));
        }
        Ok(resolved)
    }

    fn request(&self, token: &str) -> Request {
        let body = format!(
            "token={}&token_type_hint=access_token",
            net::percent::encode(token, false)
        );
        let request = Request::new("POST", self.endpoint.path())
            .header("Host", &self.endpoint.authority())
            .header("Accept", "application/json")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.as_bytes());
        match &self.client {
            Some((id, secret)) => {
                let credential = codec::base64::encode(format!("{id}:{secret}").as_bytes());
                request.header("Authorization", &format!("Basic {credential}"))
            }
            None => request,
        }
    }
}

impl Introspection for Http {
    fn introspect(&self, token: &str) -> Result<String, AuthenticateError> {
        let addresses = self.reachable()?;
        let answer = http::connect(&addresses, self.timeout)
            .and_then(|stream| http::exchange(stream, &self.request(token)))
            .map_err(|failure| {
                AuthenticateError::new(format!(
                    "the introspection endpoint {} did not answer: {failure}",
                    self.endpoint.authority()
                ))
            })?;
        judged(&answer)
    }
}

/// The body of a `200`; any other status refused, naming it.
fn judged(answer: &http::Response) -> Result<String, AuthenticateError> {
    let status = format!("{} {}", answer.status, answer.reason);
    match answer.status {
        200 => Ok(answer.text()),
        401 | 403 => Err(AuthenticateError::new(format!(
            "the authorization server refused this node's client credentials: '{status}'"
        ))),
        _ => Err(AuthenticateError::new(format!(
            "the introspection endpoint answered '{status}' and not 200"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_https_endpoint_is_refused_when_it_is_configured_and_says_why() {
        let failure = Http::at("https://as.example/introspect").expect_err("refused");

        assert!(failure.message.contains("plain HTTP/1.1 only"), "{failure}");
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

        assert_eq!(endpoint.endpoint.authority(), "[::1]:9000");
        assert_eq!(endpoint.endpoint.path(), "/oauth/introspect");
        assert_eq!((plain.endpoint.port(), plain.endpoint.path()), (80, "/"));
    }

    #[test]
    fn a_401_names_the_credentials_and_another_status_names_itself() {
        let answer = |status: u16, reason: &str| http::Response {
            status,
            reason: reason.to_string(),
            ..http::Response::default()
        };

        assert!(
            judged(&answer(401, "Unauthorized"))
                .expect_err("refused")
                .message
                .contains("client credentials")
        );
        assert!(
            judged(&answer(503, "Service Unavailable"))
                .expect_err("refused")
                .message
                .contains("'503 Service Unavailable' and not 200")
        );
    }

    #[test]
    fn a_token_is_form_encoded_so_its_punctuation_survives_the_post() {
        let request = Http::at("http://localhost/introspect")
            .expect("a URL")
            .request("a+b/c=d.e-f");

        assert_eq!(
            request.body,
            b"token=a%2Bb%2Fc%3Dd.e-f&token_type_hint=access_token"
        );
    }
}
