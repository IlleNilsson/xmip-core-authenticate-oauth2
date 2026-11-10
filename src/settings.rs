//! What a Receive Location configures the oauth2 authenticator with,
//! declared once (ADR-0064, amendment 2026-09-26) and read through that
//! declaration.
//!
//! The introspection endpoint is required and must be `https`: a Location
//! naming a plain `http` one is refused when it is read, before any token is
//! sent anywhere. The issuer and the audience are required, as `jwt`
//! requires them: a Location that leaves either out, or gives it empty, is
//! refused when it is read, so no verifier takes a token from any issuer,
//! for anyone. The leeway on the answer's `exp` and `nbf` has a default.
//! The client's id and secret, and whether the node is online (ADR-0045),
//! are given apart from these.

use core::time::Duration;

use authenticate::AuthenticateError;
use authenticate::claims::Expected;
use authenticate::clock::Clock;
use xcore::settings::{Applies, Fixed, Given, Kind, Presence, Read, Setting, Settings};

use crate::{Http, Introspection, Verifier};

/// How far a clock may be off before the answer's `exp` and `nbf` bite.
pub const LEEWAY: Duration = Duration::from_secs(60);

/// The oauth2 authenticator's settings.
pub const SETTINGS: &Settings = &Settings {
    technology: "xmip-core-authenticate-oauth2",
    settings: &[
        Setting {
            name: "introspection_endpoint",
            kind: Kind::Address,
            presence: Presence::Required,
            meaning: "The authorization server's introspection endpoint (RFC 7662), an https \
                      URL; plain http is refused.",
            applies: Applies::Receive,
        },
        Setting {
            name: "issuer",
            kind: Kind::Text,
            presence: Presence::Required,
            meaning: "The issuer an introspection answer's `iss` must be, exactly.",
            applies: Applies::Receive,
        },
        Setting {
            name: "audience",
            kind: Kind::Text,
            presence: Presence::Required,
            meaning: "The audience an introspection answer's `aud` must name.",
            applies: Applies::Receive,
        },
        Setting {
            name: "leeway",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(LEEWAY)),
            meaning: "How far a clock may be off before an answer's `exp` and `nbf` bite.",
            applies: Applies::Receive,
        },
    ],
};

/// What a Receive Location `given`, read through [`SETTINGS`].
fn read(given: &[(String, Given)]) -> Result<Read, AuthenticateError> {
    SETTINGS
        .read(Applies::Receive, given)
        .map_err(|refused| AuthenticateError::new(refused.to_string()))
}

/// Whole seconds, as the capability's clock counts them.
fn seconds(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

impl Http {
    /// The introspection endpoint a Receive Location `given`.
    ///
    /// # Errors
    ///
    /// Where the settings are refused — the endpoint, the issuer or the
    /// audience missing, each named — and where the endpoint is not an
    /// `https` URL.
    pub fn configured(given: &[(String, Given)]) -> Result<Self, AuthenticateError> {
        Self::at(read(given)?.text("introspection_endpoint"))
    }
}

impl Verifier {
    /// Asks `server` about tokens `expected` names the issuer and audience
    /// of, requiring no scope, with the default [`LEEWAY`].
    #[must_use]
    pub fn new(server: impl Introspection + 'static, expected: Expected) -> Self {
        Self {
            server: Box::new(server),
            expected,
            scopes: Vec::new(),
            principal: None,
            client: None,
            clock: Clock::system(seconds(LEEWAY)),
        }
    }

    /// Asks `server` with the issuer, audience and leeway a Receive Location
    /// `given`.
    ///
    /// # Errors
    ///
    /// Where the settings are refused — the endpoint, the issuer or the
    /// audience missing, a setting unknown or of another kind, each named —
    /// or the issuer or the audience is empty.
    pub fn configured(
        server: impl Introspection + 'static,
        given: &[(String, Given)],
    ) -> Result<Self, AuthenticateError> {
        let read = read(given)?;
        let expected = Expected::new(read.text("issuer"), read.text("audience"))?;
        Ok(Self::new(server, expected).with_leeway(seconds(read.duration("leeway"))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn given(pairs: &[(&str, &str)]) -> Vec<(String, Given)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), Given::Text((*value).to_string())))
            .collect()
    }

    #[test]
    fn the_declaration_is_sound() {
        assert_eq!(SETTINGS.problems(), Vec::<String>::new());
    }

    /// A whole Location: the endpoint, the issuer and the audience, then
    /// `more`, which may give one of them again to replace it.
    fn location(more: &[(&str, &str)]) -> Vec<(String, Given)> {
        let mut pairs = vec![
            ("introspection_endpoint", "https://as.example/introspect"),
            ("issuer", "https://as.example"),
            ("audience", "xmip"),
        ];
        pairs.retain(|(name, _)| more.iter().all(|(other, _)| other != name));
        pairs.extend_from_slice(more);
        given(&pairs)
    }

    fn refusal(given: &[(String, Given)]) -> String {
        let server = Http::at("https://as.example/introspect").expect("https");
        match Verifier::configured(server, given) {
            Ok(_) => panic!("refused"),
            Err(refused) => refused.message,
        }
    }

    #[test]
    fn an_http_endpoint_is_refused_when_the_configuration_is_read() {
        let plain = Http::configured(&location(&[(
            "introspection_endpoint",
            "http://127.0.0.1:8080/introspect",
        )]))
        .expect_err("plain http");
        let missing = Http::configured(&[]).expect_err("no endpoint");

        assert!(plain.message.contains("is not https"), "{plain}");
        assert!(
            missing.message.contains(
                "xmip-core-authenticate-oauth2 requires \"introspection_endpoint\", and it is \
                 missing"
            ),
            "{missing}"
        );
        Http::configured(&location(&[])).expect("https");
    }

    #[test]
    fn a_configuration_without_an_issuer_or_an_audience_is_refused_in_words() {
        let without = |name: &str| {
            let mut pairs = location(&[]);
            pairs.retain(|(named, _)| named != name);
            refusal(&pairs)
        };

        assert_eq!(
            without("issuer"),
            "xmip-core-authenticate-oauth2 requires \"issuer\", and it is missing"
        );
        assert_eq!(
            without("audience"),
            "xmip-core-authenticate-oauth2 requires \"audience\", and it is missing"
        );
        assert!(
            refusal(&location(&[("issuer", " ")])).contains("one is empty"),
            "an empty issuer is no issuer"
        );
        assert!(
            refusal(&location(&[("audience", "")])).contains("one is empty"),
            "an empty audience is no audience"
        );
        let server = Http::at("https://as.example/introspect").expect("https");
        assert!(Verifier::configured(server, &location(&[])).is_ok());
    }

    #[test]
    fn the_configured_leeway_is_read() {
        let refused = refusal(&location(&[("leeway", "soon")]));

        assert!(
            refused.contains("\"leeway\""),
            "a leeway that is no duration: {refused}"
        );
    }
}
