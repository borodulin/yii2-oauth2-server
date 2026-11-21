3.0.0 under development
-----------------------
Security release with breaking changes, see "Upgrading to 3.0" in README.

- Sec: confidential clients must authenticate in the authorization code grant also with PKCE (a leaked code could be redeemed with just the verifier); public clients are clients without a secret and public key
- Sec: logged-in users are no longer authorized on a plain GET: `AuthorizeFilter` requires a consent step (`finishAuthorization($approved)` on POST) unless `autoApprove`
- Sec: the authorization request in the session is a plain array that expires after 10 minutes and is validated again; no serialized models with the client secret, no `unserialize()`
- Sec: PKCE accepts only S256 by default, checks challenge/verifier formats and rejects a verifier for a code issued without a challenge (downgrade)
- Sec: tokens and codes are stored as SHA-256 hashes, client secrets as bcrypt hashes; existing ones are migrated in place
- Sec: reuse of a code or rotated refresh token revokes the tokens of that user and client
- Sec: HTTP Basic together with body credentials is rejected
- Sec: password grant timing no longer reveals existing usernames
- Sec: `access_token` in the query string is accepted only with `TokenAuth::$allowQueryToken`
- Sec: JWT: `JwtValidator::$audience` must be configured (was taken from the Host header), `jti` is required and replay protection fails closed, client assertions cannot be used as JWT bearer grants, one generic error for clients that may not use the grant
- Enh: JWT bearer grant (RFC 7523, 2.1), disabled by default; clients must list it explicitly in `grant_type`
- Enh: JWT client authentication with `client_assertion` (RFC 7523, 2.2)
- Enh: token endpoint errors follow RFC 6749 5.2 (`error`, `error_description`, 401 for `invalid_client`)
- Enh: `TokenAuth` sends `WWW-Authenticate` with `error="invalid_token"` / `"insufficient_scope"`, 403 for insufficient scope, accepts a lowercase `bearer` scheme (RFC 6750)
- Enh: `iss` in authorization responses (RFC 9207) with `$issuer`
- Enh: `Client::generateSecret()`, `Client::isPublic()`; translations are registered automatically; `yii oauth2/clear` reports what it deleted
- Enh: new migrations `m261122_120000_oauth_jwt` (`public_key`) and `m261123_120000_oauth_v3` (hashing, `used` columns, indexes); the base migration works on SQLite
- Enh: PHPStan (level 5) in CI; tests run the package migrations
- Chg: the abandoned `jakeasmith/http_build_url` dependency is removed; redirect URIs are built by `conquer\oauth2\Uri`, which keeps the registered URI as is
- Bug: authorization errors were 400 pages instead of redirects to the client; implicit errors go in the fragment
- Bug: the README flow issued two codes per login
- Bug: `oauth2_client.grant_type` was not checked at the authorization endpoint
- Bug: loopback and custom scheme redirect URIs were rejected by the url validator (RFC 8252)
- Bug: array parameters (`scope`, `username`, `password`) caused 500 errors
- Bug: a narrowed scope on refresh also narrowed the new refresh token; scopes removed from the client were refreshed
- Bug: public clients could not refresh tokens
- Bug: request parameters that are not sent overwrote configured defaults
- Bug: `getUser()` of the token models returns null instead of a broken relation when the identity class has no primary key
- Bug: `Client::validate()` failed on databases without `public_key`

2.1.0
-----
- Sec: authorization codes and refresh tokens are redeemed atomically: concurrent requests with the same code or refresh token no longer both get tokens
- Sec: `TokenAction` accepts only POST and rejects secrets, codes, refresh tokens and passwords in the query string (`$allowGet` restores the old behaviour)
- Sec: token responses are sent with `Cache-Control: no-store` and `Pragma: no-cache` (RFC 6749, 5.1)
- Sec: the authorization request stored in the session is removed after `finishAuthorization()`; later logins in the same session no longer issue codes to the previous client
- Enh: HTTP Basic client authentication (RFC 6749, 2.3.1); requires Yii 2.0.14+
- Bug: tokens without a scope crashed `TokenAuth` on PHP 8.1+ (`trim(null)` deprecation turned into an exception by Yii)
- Bug: token endpoint errors (for example an invalid scope) were sent as redirects to the client
- Bug: `TokenAuth` returns null when the request has no access token, so `optional` actions and `CompositeAuth` work and a 401 challenge is sent; unknown users get 401 instead of 400
- Bug: scopes separated by several spaces were rejected

2.0.0
-----
Security release. See "Upgrading to 2.0" in README.

- Sec: `redirect_uri` must exactly match a registered URI (was a case-insensitive prefix match that allowed redirecting codes and tokens to attacker-controlled hosts)
- Sec: authorization code grant verifies that the code was issued to the requesting client
- Sec: authorization code grant requires client authentication (`client_secret`), or a PKCE `code_verifier` for codes issued with a `code_challenge`
- Sec: refresh token grant verifies that the token was issued to the requesting client
- Sec: expiration of authorization codes and refresh tokens is checked on use
- Sec: `Client::$grant_type` (permitted grant types) is enforced
- Sec: password grant requires `client_secret`
- Sec: implicit grant is disabled by default (`AuthorizeFilter::$allowImplicit = false`)
- Enh: PKCE support (RFC 7636), new migration `m261103_120000_oauth_pkce`
- Enh: several redirect URIs per client (whitespace-separated)
- Enh: refresh token grant supports narrowing `scope`
- Bug #25: token response of the authorization code grant returns the granted scope
- Bug: authorization request without `redirect_uri` uses the registered client URI
- Bug: token endpoint errors are returned as JSON instead of redirects
- Bug: `user` relation of token models was built incorrectly
- Bug: `TokenAuth::handleFailure()` responds with 401
- Bug: array-typed request parameters are rejected instead of causing PHP errors
- Enh: PHP 8 support, CI on GitHub Actions

1.8.0
-----
- Enh: Internationalization support

1.7.0
-----
- Bug #37: Fixed `conquer\oauth2\TokenAuth` behavior when multiple Authorization headers are present
- Bug #32: `conquer\oauth2\BaseModel` caches request
- Enh #24: Client Credentials grant type support
- Enh: Added `scopes` setting to `conquer\oauth2\TokenAuth`
- Enh: Added migrations namespace
