#![forbid(unsafe_code)]

//! Authenticate by oauth2: verifies a token by introspection at the
//! authorization server.
//!
//! An OAuth 2.0 access token says nothing a resource server can check by
//! looking at it; RFC 7662 has the resource server ask whoever issued it.
//! The first gate presented the token's subject as the claim, with the token
//! riding as the `oauth2.token` proof — or as `bearer.token`, where what read
//! it off the `Authorization` header called it that. This gate posts the
//! token to the introspection endpoint the configuration names and holds the
//! answer to account: `active` is true, `exp` has not passed and `nbf` has
//! come with the configured leeway, the issuer and audience are the expected
//! ones where any are expected, every scope the node requires is in `scope`,
//! and the subject — `sub`, or `client_id` where the token was issued to a
//! client on its own behalf and has no `sub` — is the value that was claimed.
//!
//! Offline is the default (ADR-0045): the call is made only where the
//! endpoint is loopback or the configuration says the node is online, and is
//! otherwise refused with that reason — see [`introspection`]. Nothing is
//! cached: every verification is one call, so a token revoked at the server
//! is refused at the next arrival.
//!
//! What this does not cover: a JWT access token validated locally (RFC 9068)
//! is `jwt`'s gate and not this one; TLS to the endpoint is the host's (see
//! [`Introspection`]).
//!
//! What the server answered is learned and handed to the gate in the
//! `Conclusion`: the token's `scope` under the name `authorize/scope` reads,
//! its `client_id` as [`CLIENT`], and its `username` as `principal.user`
//! where it is a user principal name. None of it was claimed; an opaque
//! token says nothing until the server is asked.
//!
//! A node that expects one account says so with
//! [`Verifier::expecting_principal`]: the answer's `username` is then read
//! as the identify capability's `UserPrincipalName` and must be the same
//! account, however either was spelled (ADR-0054). A service is expected by
//! its `client_id` with [`Verifier::expecting_client`], compared as text: a
//! client id is whatever the server issued, often a GUID, and is no service
//! principal name.

pub mod introspection;

pub use introspection::{Http, Introspection};

use authenticate::clock::{Clock, Window};
use authenticate::{AuthenticateError, Authenticator, Conclusion, Presented};
use context::Verified;
use identify::UserPrincipalName;
use identify::evidence::{self, BEARER_TOKEN, SCOPE};
use serde_json::Value;
use xcore::{Mechanism, mechanism};

/// The proof an oauth2 claim carries its token under.
pub const TOKEN: &str = "oauth2.token";
/// The evidence name the token's `client_id` is learned under.
pub const CLIENT: &str = "oauth2.client";

/// The oauth2 authenticator: where to ask, and what the answer must say.
pub struct Verifier {
    server: Box<dyn Introspection>,
    issuer: Option<String>,
    audience: Option<String>,
    scopes: Vec<String>,
    principal: Option<UserPrincipalName>,
    client: Option<String>,
    clock: Clock,
}

impl Verifier {
    /// Asks `server`, expecting no issuer, audience or scope, with sixty
    /// seconds of leeway.
    #[must_use]
    pub fn new(server: impl Introspection + 'static) -> Self {
        Self {
            server: Box::new(server),
            issuer: None,
            audience: None,
            scopes: Vec::new(),
            principal: None,
            client: None,
            clock: Clock::system(60),
        }
    }

    /// Refuse a token whose `iss` is not this.
    #[must_use]
    pub fn expecting_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Refuse a token whose `aud` does not name this.
    #[must_use]
    pub fn expecting_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Refuse a token whose `scope` lacks this. May be said more than once.
    #[must_use]
    pub fn requiring_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Refuse a token whose `username` is not this account. Any spelling of
    /// the same account meets it.
    #[must_use]
    pub fn expecting_principal(mut self, principal: UserPrincipalName) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Refuse a token whose `client_id` is not this, compared as text.
    #[must_use]
    pub fn expecting_client(mut self, client: impl Into<String>) -> Self {
        self.client = Some(client.into());
        self
    }

    /// How far a clock may be off before `exp` and `nbf` bite.
    #[must_use]
    pub fn with_leeway(mut self, seconds: i64) -> Self {
        self.clock = self.clock.forgiving(seconds);
        self
    }

    /// Where the time comes from; the tests pin it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = self.clock.reading(clock);
        self
    }

    fn check(&self, answer: &Value, subject: &str) -> Result<(), AuthenticateError> {
        let text = |name: &str| answer.get(name).and_then(Value::as_str);
        match answer.get("active").and_then(Value::as_bool) {
            Some(true) => {}
            Some(false) => {
                return Err(AuthenticateError::new(
                    "the authorization server says the token is not active: \
                     expired, revoked, or never its own",
                ));
            }
            None => {
                return Err(AuthenticateError::new(
                    "the introspection response has no boolean `active`",
                ));
            }
        }
        let at = |name: &str| answer.get(name).and_then(Value::as_i64);
        self.clock
            .admits(Window::between(at("nbf"), at("exp")))
            .map_err(|outside| AuthenticateError::new(format!("the token {outside}")))?;
        if let Some(issuer) = &self.issuer
            && text("iss") != Some(issuer.as_str())
        {
            return Err(AuthenticateError::new(format!(
                "the token's issuer is not '{issuer}'"
            )));
        }
        if let Some(audience) = &self.audience
            && !names(answer.get("aud"), audience)
        {
            return Err(AuthenticateError::new(format!(
                "the token's audience does not name '{audience}'"
            )));
        }
        let granted: Vec<&str> = text("scope").unwrap_or_default().split(' ').collect();
        if let Some(missing) = self
            .scopes
            .iter()
            .find(|scope| !granted.contains(&scope.as_str()))
        {
            return Err(AuthenticateError::new(format!(
                "the token does not carry the scope '{missing}' this node requires"
            )));
        }
        match text("sub").or_else(|| text("client_id")) {
            Some(named) if named == subject => Ok(()),
            Some(_) => Err(AuthenticateError::new(
                "the token's subject is not the claimed value",
            )),
            None => Err(AuthenticateError::new(
                "the introspection response names no `sub` and no `client_id`",
            )),
        }
    }
}

/// Where an account or a client is expected, the answer names it.
fn check_names(verifier: &Verifier, answer: &Value) -> Result<(), AuthenticateError> {
    let text = |name: &str| answer.get(name).and_then(Value::as_str);

    if let Some(expected) = &verifier.principal {
        let username = text("username").unwrap_or_default();
        match UserPrincipalName::parse(username) {
            Some(named) if named.is(expected) => {}
            Some(named) => {
                return Err(AuthenticateError::new(format!(
                    "the token's username is '{named}' and this node expects '{expected}'"
                )));
            }
            None => {
                return Err(AuthenticateError::new(format!(
                    "the token's username '{username}' is not a user principal name and \
                     this node expects '{expected}'"
                )));
            }
        }
    }
    if let Some(expected) = &verifier.client
        && text("client_id") != Some(expected.as_str())
    {
        return Err(AuthenticateError::new(format!(
            "the token's client_id is '{}' and this node expects '{expected}'",
            text("client_id").unwrap_or_default()
        )));
    }
    Ok(())
}

/// Whether an `aud`, a string or an array of them, names `audience`.
fn names(aud: Option<&Value>, audience: &str) -> bool {
    match aud {
        Some(Value::String(one)) => one == audience,
        Some(Value::Array(many)) => many.iter().any(|one| one.as_str() == Some(audience)),
        _ => false,
    }
}

impl Authenticator for Verifier {
    fn mechanism(&self) -> Mechanism {
        mechanism::oauth2()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        self.conclude(presented)
            .map(|conclusion| conclusion.verified)
    }

    fn conclude(&self, presented: &Presented) -> Result<Conclusion, AuthenticateError> {
        let name = presented.mechanism.name();
        if name != self.mechanism().name() {
            return Err(AuthenticateError::new(format!(
                "'{name}' was presented and this authenticator verifies oauth2"
            )));
        }
        let token = presented
            .proof(TOKEN)
            .or_else(|| presented.proof(evidence::BEARER_TOKEN))
            .ok_or_else(|| {
                AuthenticateError::new(format!(
                    "no {TOKEN} proof and no {BEARER_TOKEN} proof was presented"
                ))
            })?;

        let body = self.server.introspect(token)?;
        let answer: Value = serde_json::from_str(&body).map_err(|failure| {
            AuthenticateError::new(format!("the introspection response is not JSON: {failure}"))
        })?;
        self.check(&answer, &presented.value)?;
        check_names(self, &answer)?;

        Ok(learned_from(&answer))
    }
}

/// What an active token's answer teaches the gate.
fn learned_from(answer: &Value) -> Conclusion {
    let text = |name: &str| {
        answer
            .get(name)
            .and_then(Value::as_str)
            .filter(|said| !said.is_empty())
    };
    let mut conclusion = Conclusion::proven();

    if let Some(scope) = text("scope") {
        conclusion = conclusion.learning(SCOPE, scope);
    }
    if let Some(client) = text("client_id") {
        conclusion = conclusion.learning(CLIENT, client);
    }
    if let Some(user) = text("username").and_then(UserPrincipalName::parse) {
        conclusion = conclusion.learning(evidence::PRINCIPAL_USER, user.to_string());
    }

    conclusion
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    const NOW: i64 = 1_800_000_000;

    /// An authorization server on loopback that answers one introspection
    /// request the way RFC 7662 section 2.2 says, and hands back what it was
    /// asked.
    fn server(status: &'static str, answer: String) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let url = format!(
            "http://{}/introspect",
            listener.local_addr().expect("an address")
        );
        let (asked, received) = mpsc::channel();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !complete(&request) {
                let read = stream.read(&mut buffer).expect("a request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                answer.len()
            );
            stream.write_all(response.as_bytes()).expect("a response");
            asked
                .send(String::from_utf8_lossy(&request).into_owned())
                .expect("a listener");
        });

        (url, received)
    }

    /// Head and the `Content-Length` it promises have both arrived.
    fn complete(request: &[u8]) -> bool {
        let text = String::from_utf8_lossy(request);
        let Some((head, body)) = text.split_once("\r\n\r\n") else {
            return false;
        };
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .and_then(|length| length.parse::<usize>().ok())
            .unwrap_or(0);
        body.len() >= length
    }

    fn active(extra: &str) -> String {
        let exp = NOW + 300;
        format!(
            concat!(
                r#"{{"active":true,"sub":"partner-x","#,
                r#""scope":"orders:read orders:write","exp":{exp}{extra}}}"#
            ),
            exp = exp,
            extra = extra
        )
    }

    fn verifier(url: &str) -> Verifier {
        let endpoint = Http::at(url)
            .expect("a URL")
            .as_client("xmip-node", "s3cret");
        Verifier::new(endpoint).with_clock(|| NOW)
    }

    fn presented(token: &str) -> Presented {
        Presented::passed(mechanism::oauth2(), "partner-x").with_proof(TOKEN, token)
    }

    #[test]
    fn an_active_token_is_proven_by_asking_the_server_over_loopback() {
        let (url, asked) = server("200 OK", active(""));

        let verified = verifier(&url)
            .requiring_scope("orders:read")
            .verify(&presented("mF_9.B5f-4/1JqM"))
            .expect("proven");
        let request = asked.recv().expect("the request");

        assert_eq!(verified, Verified::Proven);
        assert!(request.starts_with("POST /introspect HTTP/1.1\r\n"));
        assert!(request.contains("Authorization: Basic eG1pcC1ub2RlOnMzY3JldA=="));
        assert!(request.ends_with("token=mF_9.B5f-4%2F1JqM&token_type_hint=access_token"));
    }

    #[test]
    fn what_the_server_answered_is_learned_and_handed_to_the_gate() {
        let extra = r#","username":"PARTNERX\\jane","client_id":"xmip-partner""#;
        let (url, _asked) = server("200 OK", active(extra));

        let conclusion = verifier(&url)
            .conclude(&presented("mF_9.B5f-4/1JqM"))
            .expect("proven");

        assert_eq!(conclusion.verified, Verified::Proven);
        assert_eq!(conclusion.learned(SCOPE), Some("orders:read orders:write"));
        assert_eq!(conclusion.learned(CLIENT), Some("xmip-partner"));
        assert_eq!(
            conclusion.learned(evidence::PRINCIPAL_USER),
            Some("jane@partnerx")
        );
    }

    fn jane() -> UserPrincipalName {
        UserPrincipalName::parse("PARTNERX\\jane").expect("a name")
    }

    #[test]
    fn a_username_spelled_another_way_is_the_account_the_node_expects() {
        let client = "2f1c9a0e-5b7d-4c3a-9e21-0d6b8a4f7c55";
        let extra = format!(r#","username":"Jane@PartnerX","client_id":"{client}""#);
        let (url, _asked) = server("200 OK", active(&extra));

        let verified = verifier(&url)
            .expecting_principal(jane())
            .expecting_client(client)
            .verify(&presented("opaque"));

        assert_eq!(verified.expect("proven"), Verified::Proven);
    }

    #[test]
    fn another_account_and_another_client_are_each_refused_naming_both() {
        let extra = r#","username":"mallory@partnerx","client_id":"reports""#;
        let (url, _asked) = server("200 OK", active(extra));
        let account = verifier(&url)
            .expecting_principal(jane())
            .verify(&presented("opaque"))
            .expect_err("refused");
        let (url, _asked) = server("200 OK", active(extra));
        let client = verifier(&url)
            .expecting_client("Reports")
            .verify(&presented("opaque"))
            .expect_err("refused");
        let (url, _asked) = server("200 OK", active(r#","username":"jane""#));
        let bare = verifier(&url)
            .expecting_principal(jane())
            .verify(&presented("opaque"))
            .expect_err("refused");

        assert_eq!(
            account.message,
            "the token's username is 'mallory@partnerx' and this node expects 'jane@partnerx'"
        );
        assert_eq!(
            client.message,
            "the token's client_id is 'reports' and this node expects 'Reports'"
        );
        assert!(bare.message.contains("'jane' is not a user principal name"));
    }

    #[test]
    fn a_token_the_server_calls_inactive_is_refused_as_such() {
        let (url, _asked) = server("200 OK", r#"{"active":false}"#.to_string());

        let failure = verifier(&url)
            .verify(&presented("revoked"))
            .expect_err("refused");

        assert!(failure.message.contains("not active"));
    }

    #[test]
    fn a_token_without_a_required_scope_is_refused_by_the_scope() {
        let (url, _asked) = server("200 OK", active(""));

        let failure = verifier(&url)
            .requiring_scope("orders:delete")
            .verify(&presented("token"))
            .expect_err("refused");

        assert!(failure.message.contains("'orders:delete'"));
    }

    #[test]
    fn a_bearer_proof_is_read_and_a_subject_that_is_not_the_claim_is_refused() {
        let (url, _asked) = server("200 OK", active(""));
        let claim = Presented::passed(mechanism::oauth2(), "someone-else")
            .with_proof(evidence::BEARER_TOKEN, "token");

        let failure = verifier(&url).verify(&claim).expect_err("refused");

        assert!(failure.message.contains("subject"));
    }

    #[test]
    fn an_answer_the_server_has_let_expire_is_refused_by_its_expiry() {
        let answer = format!(r#"{{"active":true,"sub":"partner-x","exp":{}}}"#, NOW - 300);
        let (url, _asked) = server("200 OK", answer);

        let failure = verifier(&url)
            .verify(&presented("token"))
            .expect_err("refused");

        assert!(failure.message.contains("expired"));
    }

    #[test]
    fn another_audience_is_refused_and_an_array_of_audiences_is_read() {
        let (url, _asked) = server("200 OK", active(r#","aud":["billing","xmip"]"#));
        let (other, _asked_other) = server("200 OK", active(r#","aud":"billing""#));

        let named = verifier(&url)
            .expecting_audience("xmip")
            .verify(&presented("token"));
        let failure = verifier(&other)
            .expecting_audience("xmip")
            .verify(&presented("token"))
            .expect_err("refused");

        assert_eq!(named.expect("proven"), Verified::Proven);
        assert!(failure.message.contains("audience"));
    }

    #[test]
    fn a_server_that_refuses_the_nodes_credentials_is_named_as_the_reason() {
        let (url, _asked) = server("401 Unauthorized", String::new());

        let failure = verifier(&url)
            .verify(&presented("token"))
            .expect_err("refused");

        assert!(failure.message.contains("client credentials"));
    }

    #[test]
    fn an_offline_node_does_not_call_a_server_beyond_itself() {
        let endpoint = Http::at("http://as.example/introspect").expect("a URL");

        let failure = Verifier::new(endpoint)
            .verify(&presented("token"))
            .expect_err("refused");

        assert!(failure.message.contains("offline (ADR-0045)"));
    }

    #[test]
    fn another_mechanism_and_a_missing_proof_are_each_refused_by_name() {
        let gate = Verifier::new(Http::at("http://127.0.0.1:9/").expect("a URL"));
        let other = Presented::passed(mechanism::bearer(), "mF_9.B5f…");
        let bare = Presented::passed(mechanism::oauth2(), "partner-x");

        let not_ours = gate.verify(&other).expect_err("refused");
        let missing = gate.verify(&bare).expect_err("refused");

        assert!(not_ours.message.contains("'bearer' was presented"));
        assert!(missing.message.contains("oauth2.token"));
    }
}
