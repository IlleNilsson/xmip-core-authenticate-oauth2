# xmip-core-authenticate-oauth2

Authenticate by oauth2: verifies a token by introspection at the authorization server. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It asks the authorization server's RFC 7662 introspection endpoint whether a
token is active, and checks the window `nbf` and `exp` give where the answer
gives them, that `iss` is the configured issuer and `aud` names the
configured audience — the checks of `authenticate::claims`, which `jwt`,
`oidc` and `saml` make too — the required scopes, and that `sub` is the
claim. An answer naming no `iss` or no `aud` is refused.

The call goes through Xmip's minimal HTTP/1.1 client in
[xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net),
always in Xmip's TLS in
[xmip-core-library-tls](https://github.com/IlleNilsson/xmip-core-library-tls),
against the operating system's trust store or one the configuration gives. A
plain `http` endpoint is refused when it is configured, loopback included:
the token and the client's secret are never sent in the clear. The call is
made only where configuration says the node is online or the endpoint is
loopback, and is refused saying why otherwise (ADR-0045). Local JWT
access-token validation is `jwt`'s.

Its settings are declared in `settings.rs` through `xcore::settings`:

| Setting | Default | Meaning |
| --- | --- | --- |
| `introspection_endpoint` | required | The authorization server's introspection endpoint (RFC 7662), an `https` URL; plain `http` is refused. |
| `issuer` | required | The issuer an introspection answer's `iss` must be, exactly. |
| `audience` | required | The audience an introspection answer's `aud` must name. |
| `leeway` | `60s` | How far a clock may be off before an answer's `exp` and `nbf` bite. |

A configuration without the issuer or the audience, or with either empty, is
refused when it is read, naming the setting, as `jwt` refuses it. The
client's id and secret are given apart from these.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
