//! What a Receive Location configures the oauth2 authenticator with,
//! declared once (ADR-0064, amendment 2026-09-26) and read through that
//! declaration.
//!
//! The introspection endpoint is required and must be `https`: a Location
//! naming a plain `http` one is refused when it is read, before any token is
//! sent anywhere. The leeway on the answer's `exp` and `nbf` has a default.
//! The client's id and secret, and whether the node is online (ADR-0045),
//! are given apart from these.

use core::time::Duration;

use authenticate::AuthenticateError;
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
    /// Where the settings are refused, each named, and where the endpoint is
    /// not an `https` URL.
    pub fn configured(given: &[(String, Given)]) -> Result<Self, AuthenticateError> {
        Self::at(read(given)?.text("introspection_endpoint"))
    }
}

impl Verifier {
    /// Asks `server`, expecting no issuer, audience or scope, with the
    /// default [`LEEWAY`].
    #[must_use]
    pub fn new(server: impl Introspection + 'static) -> Self {
        Self {
            server: Box::new(server),
            issuer: None,
            audience: None,
            scopes: Vec::new(),
            principal: None,
            client: None,
            clock: Clock::system(seconds(LEEWAY)),
        }
    }

    /// Asks `server` with the leeway a Receive Location `given`.
    ///
    /// # Errors
    ///
    /// Where the settings are refused, each named.
    pub fn configured(
        server: impl Introspection + 'static,
        given: &[(String, Given)],
    ) -> Result<Self, AuthenticateError> {
        let leeway = read(given)?.duration("leeway");
        Ok(Self::new(server).with_leeway(seconds(leeway)))
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

    #[test]
    fn an_http_endpoint_is_refused_when_the_configuration_is_read() {
        let plain = Http::configured(&given(&[(
            "introspection_endpoint",
            "http://127.0.0.1:8080/introspect",
        )]))
        .expect_err("plain http");
        let missing = Http::configured(&[]).expect_err("no endpoint");

        assert!(plain.message.contains("is not https"), "{plain}");
        assert_eq!(
            missing.message,
            "xmip-core-authenticate-oauth2 requires \"introspection_endpoint\", and it is missing"
        );
        Http::configured(&given(&[(
            "introspection_endpoint",
            "https://as.example/introspect",
        )]))
        .expect("https");
    }

    #[test]
    fn the_configured_leeway_is_read() {
        let server = Http::at("https://as.example/introspect").expect("https");

        let refused = Verifier::configured(server, &given(&[("leeway", "soon")]));

        assert!(refused.is_err(), "a leeway that is no duration is refused");
    }
}
