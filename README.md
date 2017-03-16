Yii2 OAuth 2.0 Server
=================

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

To create database tables run migration command
```
$ yii migrate --migrationPath=@conquer/oauth2/migrations
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

If you want to use Resource Owner Password Credentials Grant, implement `\conquer\oauth2\OAuth2IdentityInterface` and increase security issues by add RateLimiter in AuthController

```php
use conquer\oauth2\OAuth2IdentityInterface;
use highweb\ratelimiter\UserRateLimiterTrait;

class User extends ActiveRecord implements IdentityInterface, OAuth2IdentityInterface
{
    use UserRateLimiterTrait;
    
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
            'rateLimiter' => [
                // Use class
                'class' => \highweb\ratelimiter\RateLimiter::className(),
    
                // The maximum number of allowed requests
                'rateLimit' => 100,
    
                // The time period for the rates to apply to
                'timePeriod' => 600,
    
                // Separate rate limiting for guests and authenticated users
                // Defaults to true
                // - false: use one set of rates, whether you are authenticated or not
                // - true: use separate rates for guests and authenticated users
                'separateRates' => false,
    
                // Whether to return HTTP headers containing the current rate limiting information
                'enableRateLimitHeaders' => false,
    
                // apply filter only for token action
                'only' => ['token']
            ]
        ];
    }
    
    /**
     * @inheritdoc
     */
    public function actions()
    {
        return [
            /**
             * Returns an access token.
             */
            'token' => [
                'class' => \conquer\oauth2\TokenAction::classname(),
                'format' => Response::FORMAT_XML,
                // enable password credentials
                'grantTypes' => [
                    'authorization_code' => 'conquer\oauth2\granttypes\Authorization',
                    'refresh_token' => 'conquer\oauth2\granttypes\RefreshToken',
                    'password' => 'conquer\oauth2\granttypes\UserCredentials',
                ]
            ],
        ];
    }
```

## License

**conquer/oauth2** is released under the MIT License. See the bundled `LICENSE` for details.
