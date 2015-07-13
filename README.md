Yii2 OAuth 2.0 Server
=================

## Description

This extension provides simple implementation of [Oauth 2.0](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-v2/) specification using Yii2 framework.

# Installation

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

# Usage

Authorization routine
```php
namespace app\controllers;

use app\models\LoginForm;

class AuthController extends \yii\web\Controller
{
    public function behaviors()
    {
        return [
            'oauth2Auth' => [
                'class' => \conquer\oauth2\AuthorizeFilter::className(),
                'only' => ['index'],
            ],
        ];
    }
    public function actions()
    {
        return [
            'token' => [
                'class' => \conquer\oauth2\TokenAction::classname(),
            ],
        ];
    }
    /**
     * Authorization routine
     */
    public function actionIndex()
    {
        $model = new LoginForm();
        if ($model->load(\Yii::$app->request->post()) && $model->login()) {
            return $this->goBack();
        } else {
            return $this->render('index', [
                'model' => $model,
            ]);
        }
    }
}
```
Usage in Api Controller
```php
class ApiController extends \yii\web\Controller
{
    public function behaviors()
    {
        return [
            'tokenAuth' => [
                'class' => \conquer\oauth2\TokenAuth::className(),
            ],
        ];
    }
    public function beforeAction($action)
    {
        $this->enableCsrfValidation = false;
        \Yii::$app->response->format = Response::FORMAT_JSON;
        return parent::beforeAction($action);
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

# License

**conquer/oauth2** is released under the MIT License. See the bundled `LICENSE.md` for details.
