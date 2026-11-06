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
