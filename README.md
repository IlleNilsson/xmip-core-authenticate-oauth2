# xmip-core-authenticate-oauth2

Authenticate by oauth2: verifies a token by introspection at the authorization server. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It asks the authorization server's RFC 7662 introspection endpoint whether a
token is active, and checks the window `nbf` and `exp` give where the answer
gives them, the issuer and audience where they are expected — the checks of
`authenticate::claims`, which `jwt`, `oidc` and `saml` make too — the
required scopes, and that `sub` is the claim.

The call goes through the estate's minimal HTTP/1.1 client in
[xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net)
and, for an `https` endpoint, the estate's TLS in
[xmip-core-library-tls](https://github.com/IlleNilsson/xmip-core-library-tls),
against the operating system's trust store or one the configuration gives. A
plain `http` endpoint is refused unless it is loopback, and is then reached
only at a loopback address. The call is made only where configuration says
the node is online or the endpoint is loopback, and is refused saying why
otherwise (ADR-0045). Local JWT access-token validation is `jwt`'s.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
