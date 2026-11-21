# Yii2 OAuth 2.0 Server

[![Latest Version](https://img.shields.io/packagist/v/conquer/oauth2.svg)](https://packagist.org/packages/conquer/oauth2)
[![Total Downloads](https://img.shields.io/packagist/dt/conquer/oauth2.svg)](https://packagist.org/packages/conquer/oauth2)
[![CI](https://github.com/borodulin/yii2-oauth2-server/actions/workflows/ci.yml/badge.svg)](https://github.com/borodulin/yii2-oauth2-server/actions/workflows/ci.yml)
[![License](https://img.shields.io/packagist/l/conquer/oauth2.svg)](LICENSE)

## Description

An OAuth 2.0 authorization server for Yii 2: authorization code (with PKCE), refresh token, client credentials,
password and JWT bearer (RFC 7523) grants, plus a filter that protects API actions with access tokens.
It follows RFC 6749, RFC 6750, RFC 7636 and the OAuth 2.0 Security BCP (RFC 9700).

## Requirements

- PHP 7.4 or 8.x (JWT support needs PHP 8.0+)
- Yii 2.0.14+

## Installation

```bash
composer require conquer/oauth2:^3.0
```

Add the [migrations](./src/migrations) to the console config as
[namespaced migrations](https://www.yiiframework.com/doc/guide/2.0/en/db-migrations#namespaced-migrations)
and run them:

```php
'controllerMap' => [
    'migrate' => [
        'class' => 'yii\console\controllers\MigrateController',
        'migrationPath' => null,
        'migrationNamespaces' => [
            'conquer\oauth2\migrations',
        ],
    ],
],
```

```sh
yii migrate/up
```

Delete expired codes and tokens periodically, e.g. from cron. Register the module for the console application:

```php
'bootstrap' => ['oauth2'],
'modules' => [
    'oauth2' => \conquer\oauth2\Module::class,
],
```

```sh
yii oauth2/clear
```

Translations of the `conquer/oauth2` category are registered automatically; configure the category yourself
to override them.

## Clients

Clients are rows of `oauth2_client` (model `conquer\oauth2\models\Client`):

- `redirect_uri`: registered redirect URIs separated by whitespace; requests must use one of them exactly;
- `grant_type`: permitted grant types separated by whitespace (`authorization_code`, `implicit`, `refresh_token`,
  `client_credentials`, `password`), empty means all except the JWT bearer grant;
- `scope`: scopes the client may request, separated by whitespace;
- `client_secret`: stored as a bcrypt hash. **Confidential** clients (server-side apps) have a secret or a
  `public_key` and must authenticate at the token endpoint, also when they use PKCE. **Public** clients (SPA, mobile
  and desktop apps) have an empty secret and no public key; they must use PKCE with `S256` and cannot use the
  client credentials and password grants.

```php
$client = new \conquer\oauth2\models\Client([
    'client_id' => 'my-app',
    'redirect_uri' => 'https://my-app.example.com/oauth/callback',
    'grant_type' => 'authorization_code refresh_token',
    'scope' => 'profile email',
]);
$secret = $client->generateSecret(); // give it to the client, only the hash is stored
$client->save();
```

## Usage

### Authorization endpoint

`AuthorizeFilter` validates the authorization request and keeps it in the session while the user logs in.
The user must then approve the request on a consent page, which posts back to the same action;
`finishAuthorization()` redirects the user agent to the client with a code, or with `access_denied`.

```php
namespace app\controllers;

use app\models\LoginForm;
use conquer\oauth2\AuthorizeFilter;
use conquer\oauth2\TokenAction;
use Yii;

class AuthController extends \yii\web\Controller
{
    public function behaviors()
    {
        return [
            'oauth2Auth' => [
                'class' => AuthorizeFilter::class,
                'only' => ['index'],
                // optional: skip the consent page for your own clients
                // 'autoApprove' => function ($request) { return $request->client->client_id === 'my-spa'; },
            ],
        ];
    }

    public function actions()
    {
        return [
            'token' => [
                'class' => TokenAction::class,
            ],
        ];
    }

    /**
     * Login form, then the consent page.
     */
    public function actionIndex()
    {
        /** @var AuthorizeFilter $oauth */
        $oauth = $this->getBehavior('oauth2Auth');

        if (Yii::$app->user->isGuest) {
            $model = new LoginForm();
            if ($model->load(Yii::$app->request->post()) && $model->login()) {
                return $this->refresh();
            }
            return $this->render('login', ['model' => $model]);
        }

        if (Yii::$app->request->isPost) {
            // the form is protected by Yii's CSRF validation
            $oauth->finishAuthorization(Yii::$app->request->post('approve') === '1');
            return null;
        }

        $request = $oauth->getAuthorizationRequest();
        return $this->render('consent', [
            'client' => $request->client,
            'scope' => $request->scope,
        ]);
    }
}
```

`consent.php`:

```php
<p><?= Html::encode($client->client_id) ?> asks for: <?= Html::encode($scope) ?></p>
<?= Html::beginForm() ?>
<?= Html::submitButton('Allow', ['name' => 'approve', 'value' => '1']) ?>
<?= Html::submitButton('Deny', ['name' => 'approve', 'value' => '0']) ?>
<?= Html::endForm() ?>
```

The user may also log in with a third-party provider (`yii\authclient\AuthAction`) in between: the request is kept
in the session for `AuthorizeFilter::$requestLifetime` seconds (10 minutes) and validated again when it is finished.

Options of the `code` response type (`conquer\oauth2\responsetypes\Authorization`, configure it through
`AuthorizeFilter::$responseTypes`): `requirePkce` (PKCE for confidential clients too, recommended),
`allowPlainPkce`, `issuer` (adds `iss` to responses, RFC 9207). The implicit grant is disabled by default
(`AuthorizeFilter::$allowImplicit`); don't use it for new clients.

### Token endpoint

`TokenAction` accepts only `POST` requests with parameters in the body (`allowGet` disables this check).
Clients authenticate with HTTP Basic or `client_id` + `client_secret` in the body, not both, or with a JWT
(see below). Errors are returned as `{"error": "...", "error_description": "..."}` with status 400, or 401 for
`invalid_client` (RFC 6749, 5.2).

Codes and refresh tokens can be used once. Using one again revokes the tokens issued to that user and client.
Tokens and codes are stored as SHA-256 hashes.

### Resource server

```php
class ApiController extends \yii\rest\Controller
{
    public function behaviors()
    {
        return [
            'tokenAuth' => [
                'class' => \conquer\oauth2\TokenAuth::class,
                'scopes' => ['profile'],
            ],
        ];
    }

    public function actionIndex()
    {
        $user = \Yii::$app->user->identity;
        return [
            'username' => $user->username,
            'email' => $user->email,
        ];
    }
}
```

`TokenAuth` reads the token from the `Authorization: Bearer` header or a form-encoded POST body; the `access_token`
query parameter is accepted only with `allowQueryToken`. Invalid and expired tokens get 401, insufficient scope
403, both with a `WWW-Authenticate` header (RFC 6750). Tokens of the client credentials grant have no user,
`TokenAuth` rejects them.

### Client example

A Yii application as a client:

```php
return [
...
   'components' => [
       'authClientCollection' => [
            'class' => 'yii\authclient\Collection',
            'clients' => [
                'myserver' => [
                    'class' => 'yii\authclient\OAuth2',
                    'clientId' => 'unique client_id',
                    'clientSecret' => 'client_secret',
                    'tokenUrl' => 'https://myserver.example.com/auth/token',
                    'authUrl' => 'https://myserver.example.com/auth/index',
                    'apiBaseUrl' => 'https://myserver.example.com/api',
                ],
            ],
        ],
];
```

### Password grant

The password grant is disabled by default and discouraged (RFC 9700, 2.4). To use it, add
`'password' => \conquer\oauth2\granttypes\UserCredentials::class` to `TokenAction::$grantTypes` and implement `\conquer\oauth2\OAuth2IdentityInterface`.

```php
use conquer\oauth2\OAuth2IdentityInterface;

class User extends ActiveRecord implements IdentityInterface, OAuth2IdentityInterface
{
    ...
    
    /**
     * Finds user by username
     *
     * @param string $username
     * @return static|null
     */
    public static function findIdentityByUsername($username)
    {
        return static::findOne(['username' => $username]);
    }
    
    /**
     * Validates password
     *
     * @param string $password password to validate
     * @return bool if password provided is valid for current user
     */
    public function validatePassword($password)
    {
        return Yii::$app->security->validatePassword($password, $this->password_hash);
    }
    
    ...
}
```

### JWT (RFC 7523)

Requires PHP 8.0+ and `firebase/php-jwt` 7 (earlier versions have known vulnerabilities):

```
composer require firebase/php-jwt:^7.0
```

Run `yii migrate/up`: the migration adds `oauth2_client.public_key`. Store the client's PEM encoded public key there
(RSA of at least 2048 bits, or EC P-256/P-384). Supported algorithms: RS256, RS384, RS512, ES256, ES384.

Every JWT must contain `iss`, `sub`, `aud`, `exp` and `jti`. `exp` may be at most 10 minutes in the future, and the
allowed clock skew is 60 seconds. A `jti` can be used once: it is remembered in the `cache` component, which must be
shared by all application servers and support atomic `add()` (Redis, Memcached, DB; not `DummyCache`).

The accepted audience must be configured; it is not derived from the request because the `Host` header is controlled
by the client:

```php
Yii::$container->set(\conquer\oauth2\JwtValidator::class, [
    'audience' => 'https://example.com/oauth2/token',
    // 'replayCache' => 'redisCache',
    // 'requireJti' => false, 'replayCache' => null, // not recommended: JWTs can be replayed until they expire
]);
```

**Client authentication.** Instead of `client_secret`, a client can send
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and a `client_assertion` JWT
signed with its private key, where `iss` and `sub` are its `client_id`. This works with every grant once the
client has a public key.

**JWT bearer grant.** The client exchanges a JWT (`iss`: its `client_id`, `sub`: the user ID, which must differ from
the `client_id`) for an access token of that user. A client with this grant can get tokens of any user, so the grant is disabled by default. To use it,
enable it on `TokenAction` and list it explicitly in `oauth2_client.grant_type`; an empty `grant_type` does not
allow it:

```php
'token' => [
    'class' => \conquer\oauth2\TokenAction::class,
    'grantTypes' => [
        'authorization_code' => \conquer\oauth2\granttypes\Authorization::class,
        'refresh_token' => \conquer\oauth2\granttypes\RefreshToken::class,
        'client_credentials' => \conquer\oauth2\granttypes\ClientCredentials::class,
        'urn:ietf:params:oauth:grant-type:jwt-bearer' => \conquer\oauth2\granttypes\JwtBearer::class,
    ],
],
```

Token request:

```
POST /oauth2/token
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=eyJhbGciOiJSUzI1NiJ9...&scope=read
```

### Warning

As official documentation says:

> Since this access token request utilizes the resource owner's
  password, the authorization server MUST protect the endpoint against
  brute force attacks (e.g., using rate-limitation or generating
  alerts).
  
It's strongly recommended to rate limits on token endpoint.
Fortunately, Yii2 have instruments to do this.

For further information see [Yii2 Ratelimiter](http://www.yiiframework.com/doc-2.0/yii-filters-ratelimiter.html)

## Upgrading to 3.0

Version 3.0 fixes security issues found in a review and changes several defaults. Run `yii migrate/up`:
`m261123_120000_oauth_v3` hashes existing tokens and client secrets in place (they stay valid) and cannot be
reverted. Then check:

1. **Consent.** A logged-in user is no longer authorized on a plain GET. Show a consent page and call
   `finishAuthorization($approved)` on POST (see above), or set `autoApprove` for your own clients only.
   `finishAuthorization()` on a GET request without auto approval throws.
2. **Client authentication.** Confidential clients must authenticate also when they use PKCE. Clients that used
   PKCE without a secret must become public clients: set their `client_secret` to an empty string.
3. **PKCE.** Only `S256` is accepted (`allowPlainPkce` restores `plain`); public clients must use PKCE.
4. **Secrets and tokens are hashed.** Assign a plain secret to `Client::$client_secret` and save the model, or
   use `Client::generateSecret()`; don't write secrets to the table directly. Tokens can't be read from the
   database any more: `$model->token` holds the token right after `create*()`, look tokens up with `findByToken()`.
5. **Token endpoint errors** are RFC 6749 JSON (`error`, `error_description`) instead of Yii error pages,
   with 401 for `invalid_client`. Wrong secrets are `invalid_client` (was `unauthorized_client`).
   `redirect_uri_mismatch` is replaced with `invalid_request`.
6. **Authorization errors** now really redirect to the client (they were 400 pages).
7. **Resource server.** `access_token` in the query string is rejected unless `TokenAuth::$allowQueryToken`;
   insufficient scope is 403.
8. **Authorization endpoint** checks `oauth2_client.grant_type` (`authorization_code` / `implicit`).
9. **JWT:** `JwtValidator::$audience` must be configured, `jti` is required and needs a shared cache.
10. HTTP Basic and body credentials in one request are rejected.

## Upgrading to 2.1

- The token endpoint accepts only `POST` requests with parameters in the body. If some clients still use `GET`,
  set `'allowGet' => true` on `TokenAction` until they are fixed.
- Clients may authenticate with HTTP Basic (`Authorization: Basic base64(client_id:client_secret)`).

## Upgrading to 2.0

1. Run the new migration (`yii migrate/up`), it adds PKCE columns to `oauth2_authorization_code`.
2. `redirect_uri` sent by clients must be **exactly equal** to a registered URI.
3. If `oauth2_client.grant_type` is filled, only the listed grant types are allowed for the client.
4. The implicit grant is disabled by default.

## License

**conquer/oauth2** is released under the MIT License. See the bundled [`LICENSE`](LICENSE) for details.
