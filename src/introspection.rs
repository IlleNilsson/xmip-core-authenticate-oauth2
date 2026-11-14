//! The introspection call: RFC 7662 section 2, asked of an authorization
//! server the configuration names.
//!
//! [`Introspection`] is the seam: given a token it answers the JSON the
//! server said. [`Http`] is the implementation this crate carries — one
//! `POST` of `token=<token>` as a form over the estate's minimal HTTP/1.1
//! client, `net::http`, on a TCP connection it opens and closes, with the
//! client's secret RFC 7662 section 2.1 requires as HTTP Basic.
//!
//! **TLS, always.** The token and the client's secret both prove something,
//! so the endpoint must be `https` and is reached through Xmip's own TLS
//! (`xmip-core-library-tls`), against the operating system's trust store or
//! the one the configuration gives ([`Http::trusting`]). A plain `http`
//! endpoint is refused when it is configured, loopback included: any process
//! on the host may listen on a loopback port, and TLS is what proves the
//! server is the authorization server.
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
use std::sync::Arc;
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

/// The introspection endpoint over HTTP/1.1 in TLS.
#[derive(Clone)]
pub struct Http {
    endpoint: Endpoint,
    client: Option<(String, String)>,
    online: bool,
    timeout: Duration,
    /// What the authorization server's certificate is checked by.
    settings: tls::ClientSettings,
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
    /// The endpoint at `url`: `https://host[:port]/path`. The node is taken
    /// to be offline, no client secret, five seconds to answer, the
    /// operating system's trust store.
    ///
    /// # Errors
    ///
    /// Where the URL is not an `https` URL with a host: a plain `http` one,
    /// loopback included, would carry the token and the client's secret in
    /// the clear to whoever listens there.
    pub fn at(url: &str) -> Result<Self, AuthenticateError> {
        let endpoint = Endpoint::parse(url).map_err(|refused| {
            AuthenticateError::new(format!("the introspection endpoint {refused}"))
        })?;
        if !endpoint.secure() {
            return Err(AuthenticateError::new(format!(
                "the introspection endpoint '{url}' is not https: the token and the client's \
                 secret would be sent in the clear to whoever listens at '{}'",
                endpoint.host()
            )));
        }
        Ok(Self {
            endpoint,
            client: None,
            online: false,
            timeout: Duration::from_secs(5),
            settings: tls::ClientSettings::native(),
        })
    }

    /// Verify the server's certificate against this trust store, the
    /// authorization server's own certificate authority, rather than the
    /// operating system's.
    #[must_use]
    pub fn trusting(mut self, config: Arc<tls::ClientConfig>) -> Self {
        self.settings = tls::ClientSettings::trusting(config);
        self
    }

    /// The configuration says this node may reach beyond itself.
    #[must_use]
    pub const fn online(mut self) -> Self {
        self.online = true;
        self
    }

    /// Authenticate to the endpoint as this client with its secret, in HTTP
    /// Basic.
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
                "'{host}' resolves to no loopback address, and the node is offline (ADR-0045)"
            )));
        }
        Ok(resolved)
    }

    /// One exchange over `tcp`, in TLS.
    fn exchange(
        &self,
        tcp: std::net::TcpStream,
        request: &Request,
    ) -> Result<http::Response, String> {
        let guarded = self
            .settings
            .client(self.endpoint.host(), tcp)
            .map_err(|failure| failure.message)?;
        http::exchange(guarded, request).map_err(|failure| failure.to_string())
    }

    fn request(&self, token: &str) -> Request {
        let body = format!(
            "token={}&token_type_hint=access_token",
            codec::percent::encode(token, false)
        );
        let request = Request::new("POST", self.endpoint.path())
            .header("Host", &self.endpoint.authority())
            .header("Accept", "application/json")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.as_bytes());
        match &self.client {
            Some((id, secret)) => {
                let basic = codec::base64::encode(format!("{id}:{secret}").as_bytes());
                request.header("Authorization", &format!("Basic {basic}"))
            }
            None => request,
        }
    }
}

impl Introspection for Http {
    fn introspect(&self, token: &str) -> Result<String, AuthenticateError> {
        let addresses = self.reachable()?;
        let answer = net::connect(&addresses[..], Some(self.timeout))
            .map_err(|failure| failure.to_string())
            .and_then(|stream| self.exchange(stream, &self.request(token)))
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
        200 => answer.text().map(str::to_string).map_err(|refused| {
            AuthenticateError::new(format!("the introspection endpoint's answer: {refused}"))
        }),
        401 | 403 => Err(AuthenticateError::new(format!(
            "the authorization server refused this node's client id and secret: '{status}'"
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
    fn plain_http_is_refused_when_it_is_configured_loopback_included_and_says_why() {
        for url in [
            "http://as.example/introspect",
            "http://127.0.0.1:9/introspect",
            "http://localhost/introspect",
            "http://[::1]:9000/introspect",
        ] {
            let failure = Http::at(url).expect_err("refused");

            assert!(failure.message.contains("is not https"), "{failure}");
            assert!(failure.message.contains("in the clear"), "{failure}");
        }
        assert!(Http::at("https://as.example/introspect").is_ok());
        assert!(Http::at("https://127.0.0.1:9/introspect").is_ok());
    }

    #[test]
    fn an_https_endpoint_is_asked_in_tls_and_answers_through_it() {
        let signed = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .expect("a certificate");
        let config = tls::server_config(
            signed.cert.pem().as_bytes(),
            signed.signing_key.serialize_pem().as_bytes(),
        )
        .expect("a server");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bound");
        let port = listener.local_addr().expect("an address").port();
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("a connection");
            let mut guarded = tls::server(tcp, Arc::new(config)).expect("tls");
            let request = http::read_request(&mut std::io::BufReader::new(&mut guarded))
                .expect("read")
                .expect("a request");
            let answer = http::Response::new(200).body(br#"{"active":false}"#);
            http::write_response(&mut guarded, &answer).expect("answered");
            std::io::Write::flush(&mut guarded).expect("flushed");
            request.path
        });
        let trust = tls::trusting(signed.cert.pem().as_bytes()).expect("a trust store");

        let answer = Http::at(&format!("https://127.0.0.1:{port}/introspect"))
            .expect("a URL")
            .trusting(Arc::new(trust))
            .introspect("t")
            .expect("answered");

        assert_eq!(answer, r#"{"active":false}"#);
        assert_eq!(server.join().expect("served"), "/introspect");
    }

    #[test]
    fn an_offline_node_refuses_an_endpoint_beyond_itself_and_says_why() {
        let endpoint = Http::at("https://as.example:8443/introspect").expect("a URL");

        let failure = endpoint.introspect("token").expect_err("refused");

        assert!(failure.message.contains("offline (ADR-0045)"));
        assert!(failure.message.contains("as.example"));
    }

    #[test]
    fn a_url_is_read_into_host_port_and_path() {
        let endpoint = Http::at("https://[::1]:9000/oauth/introspect").expect("a URL");
        let bare = Http::at("https://localhost").expect("a URL");

        assert_eq!(endpoint.endpoint.authority(), "[::1]:9000");
        assert_eq!(endpoint.endpoint.path(), "/oauth/introspect");
        assert_eq!((bare.endpoint.port(), bare.endpoint.path()), (443, "/"));
    }

    #[test]
    fn a_401_names_the_client_secret_and_another_status_names_itself() {
        let answer = |status: u16, reason: &str| http::Response {
            status,
            reason: reason.to_string(),
            ..http::Response::default()
        };

        assert!(
            judged(&answer(401, "Unauthorized"))
                .expect_err("refused")
                .message
                .contains("client id and secret")
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
        let request = Http::at("https://localhost/introspect")
            .expect("a URL")
            .request("a+b/c=d.e-f");

        assert_eq!(
            request.body,
            b"token=a%2Bb%2Fc%3Dd.e-f&token_type_hint=access_token"
        );
    }
}
