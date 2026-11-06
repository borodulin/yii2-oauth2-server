# Yii2 OAuth 2.0 Server

[![Latest Version](https://img.shields.io/packagist/v/conquer/oauth2.svg)](https://packagist.org/packages/conquer/oauth2)
[![Total Downloads](https://img.shields.io/packagist/dt/conquer/oauth2.svg)](https://packagist.org/packages/conquer/oauth2)
[![CI](https://github.com/borodulin/yii2-oauth2-server/actions/workflows/ci.yml/badge.svg)](https://github.com/borodulin/yii2-oauth2-server/actions/workflows/ci.yml)
[![License](https://img.shields.io/packagist/l/conquer/oauth2.svg)](LICENSE)

## Description

This extension provides simple implementation of [Oauth 2.0](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-v2/) specification using Yii2 framework.

## Requirements

- PHP 7.4 or 8.x
- Yii 2.0

## Installation

Install the extension via [Composer](https://getcomposer.org):

```bash
composer require conquer/oauth2:^1.8
```

Migrations are available from [migrations](./src/migrations) folder.

To add migrations to your application, edit the console config file to configure
[a namespaced migration](http://www.yiiframework.com/doc-2.0/guide-db-migrations.html#namespaced-migrations):

```php
'controllerMap' => [
    // ...
    'migrate' => [
        'class' => 'yii\console\controllers\MigrateController',
        'migrationPath' => null,
        'migrationNamespaces' => [
            // ...
            'conquer\oauth2\migrations',
        ],
    ],
],
```

Then issue the `migrate/up` command:

```sh
yii migrate/up
```

You also need to specify message translation source for this package:

```
'components' => [
    'i18n' => [
        'translations' => [
            'conquer/oauth2' => [
                'class' => \yii\i18n\PhpMessageSource::class,
                'basePath' => '@conquer/oauth2/messages',
            ],
        ],
    ]
],
```

## Upgrading to 2.0

Version 2.0 fixes several security issues and makes the server follow RFC 6749 / OAuth 2.0 Security BCP more strictly:

1. Run the new migration (`yii migrate/up`) — it adds PKCE columns to `oauth2_authorization_code`.
2. `redirect_uri` sent by clients must be **exactly equal** to a registered URI. Register every callback URI
   of a client in `oauth2_client.redirect_uri`, separated by whitespace.
3. The `authorization_code` grant requires `client_secret`. Public clients (SPA, mobile) must use
   PKCE instead: send `code_challenge` (+ `code_challenge_method=S256`) to the authorization endpoint
   and `code_verifier` to the token endpoint.
4. If `oauth2_client.grant_type` is filled, only the listed grant types are allowed for the client.
5. The implicit grant is disabled by default. Set `'allowImplicit' => true` on `AuthorizeFilter` if you still need it.

## Upgrading to 2.1

- The token endpoint accepts only `POST` requests with parameters in the body. If some clients still use `GET`,
  set `'allowGet' => true` on `TokenAction` until they are fixed.
- Clients may authenticate with HTTP Basic (`Authorization: Basic base64(client_id:client_secret)`).

### User consent

`AuthorizeFilter` finishes the authorization as soon as the user is logged in. If your server serves third-party
clients, show a consent page first: override `AuthorizeFilter::afterAction()` (or call
`finishAuthorization()` yourself) only after the user has approved the requested scopes.

## Usage

OAuth 2.0 Authorization usage 
```php
namespace app\controllers;

use app\models\LoginForm;

class AuthController extends \yii\web\Controller
{
    public function behaviors()
    {
        return [
            /** 
             * Checks oauth2 credentions and try to perform OAuth2 authorization on logged user.
             * AuthorizeFilter uses session to store incoming oauth2 request, so 
             * you can do additional steps, such as third party oauth authorization (Facebook, Google ...)  
             */
            'oauth2Auth' => [
                'class' => \conquer\oauth2\AuthorizeFilter::className(),
                'only' => ['index'],
            ],
        ];
    }
    public function actions()
    {
        return [
            /**
             * Returns an access token.
             */
            'token' => [
                'class' => \conquer\oauth2\TokenAction::classname(),
            ],
            /**
             * OPTIONAL
             * Third party oauth providers also can be used.
             */
            'back' => [
                'class' => \yii\authclient\AuthAction::className(),
                'successCallback' => [$this, 'successCallback'],
            ],
        ];
    }
    /**
     * Display login form, signup or something else.
     * AuthClients such as Google also may be used
     */
    public function actionIndex()
    {
        $model = new LoginForm();
        if ($model->load(\Yii::$app->request->post()) && $model->login()) {
            if ($this->isOauthRequest) {
                $this->finishAuthorization();
            } else {
                return $this->goBack();
            }
        } else {
            return $this->render('index', [
                'model' => $model,
            ]);
        }
    }
    /**
     * OPTIONAL
     * Third party oauth callback sample
     * @param OAuth2 $client
     */
    public function successCallback($client)
    {
        switch ($client::className()) {
            case GoogleOAuth::className():
                // Do login with automatic signup                
                break;
            ...
            default:
                break;
        }
        /**
         * If user is logged on, redirects to oauth client with success,
         * or redirects error with Access Denied
         */
        if ($this->isOauthRequest) {
            $this->finishAuthorization();
        }
    }
    
}
```
Api controller sample
```php
class ApiController extends \yii\rest\Controller
{
    public function behaviors()
    {
        return [
            /** 
             * Performs authorization by token
             */
            'tokenAuth' => [
                'class' => \conquer\oauth2\TokenAuth::className(),
            ],
        ];
    }
    /**
     * Returns username and email
     */
    public function actionIndex()
    {
        $user = \Yii::$app->user->identity;
        return [
            'username' => $user->username,
            'email' =>  $user->email,
        ];
    }
}
```
Sample client config
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
                    'tokenUrl' => 'http://myserver.local/auth/token',
                    'authUrl' => 'http://myserver.local/auth/index',
                    'apiBaseUrl' => 'http://myserver.local/api',
                ],
            ],
        ],
];
```

If you want to use Resource Owner Password Credentials Grant, 
implement `\conquer\oauth2\OAuth2IdentityInterface`.

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

### Warning

As official documentation says:

> Since this access token request utilizes the resource owner's
  password, the authorization server MUST protect the endpoint against
  brute force attacks (e.g., using rate-limitation or generating
  alerts).
  
It's strongly recommended to rate limits on token endpoint.
Fortunately, Yii2 have instruments to do this.

For further information see [Yii2 Ratelimiter](http://www.yiiframework.com/doc-2.0/yii-filters-ratelimiter.html)

## License

**conquer/oauth2** is released under the MIT License. See the bundled [`LICENSE`](LICENSE) for details.
