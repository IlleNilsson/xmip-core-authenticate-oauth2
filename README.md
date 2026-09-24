# xmip-core-authenticate-oauth2

Authenticate by oauth2: verifies a token by introspection at the authorization server. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It asks the authorization server's RFC 7662 introspection endpoint whether a
token is active, and checks `exp`, the required scopes and that `sub` is the
claim. It makes the call over plain HTTP, through the estate's minimal
HTTP/1.1 client in
[xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net),
only where configuration says the node
is online or the endpoint is loopback, and refuses saying why otherwise
(ADR-0045); HTTPS to the endpoint and local JWT access-token validation are not
covered.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
