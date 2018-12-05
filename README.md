Yii2 OAuth 2.0 Server
=================

[![Build Status](https://travis-ci.org/borodulin/yii2-oauth2-server.svg?branch=master)](https://travis-ci.org/borodulin/yii2-oauth2-server)

## Description

This extension provides simple implementation of [Oauth 2.0](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-v2/) specification using Yii2 framework.

## Installation

The preferred way to install this extension is through [composer](http://getcomposer.org/download/). 

To install, either run

```
$ php composer.phar require conquer/oauth2 "*"
```
or add

```
"conquer/oauth2": "*"
```

to the ```require``` section of your `composer.json` file.

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
            'oauth2' => [
                'class' => \yii\i18n\PhpMessageSource::class,
                'basePath' => '@conquer/oauth2/messages',
            ],
        ],
    ]
],
```

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

**conquer/oauth2** is released under the MIT License. See the bundled `LICENSE` for details.
