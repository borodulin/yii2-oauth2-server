<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use conquer\oauth2\Oauth2Server;
use conquer\oauth2\Oauth2Exception;
use conquer\oauth2\models\Oauth2AccessToken;
use yii\base\Action;
use yii\web\Response;
use conquer\oauth2\tokentypes\Bearer;

/**
 * BearerAuth is an action filter that supports the authentication method based on OAuth2 Bearer token.
 *
 * You may use BearerAuth by attaching it as a behavior to a controller or module, like the following:
 *
 * ```php
 * public function behaviors()
 * {
 *     return [
 *         'bearerAuth' => [
 *             'class' => \conquer\oauth2\BearerAuth::className(),
 *         ],
 *     ];
 * }
 * ```
 *
 * @author Andrey Borodulin
 */
class BearerAuth extends \yii\filters\auth\AuthMethod
{
    /**
     * @var string the HTTP authentication realm
     */
    public $realm;

    /**
     * @var string the class name of the [[identity]] object.
     */
    public $identityClass;
    

    /**
     * @param \yii\base\Action $action
     * (non-PHPdoc)
     * @see \yii\filters\auth\AuthMethod::beforeAction()
     */
    public function beforeAction($action)
    {
        $response = $this->response ? : \Yii::$app->getResponse();
        
        $response->format = Response::FORMAT_JSON;

        return parent::beforeAction($action);
    }
    
    /**
     * @inheritdoc
     */
    public function authenticate($user, $request, $response)
    {
        $bearer = new Bearer();
        
        $accessToken = $bearer->getBearerToken();
        
        /* @var $user \yii\web\User */
        $identityClass = is_null($this->identityClass) ? $user->identityClass : $this->identityClass;
        
        $identity = $identityClass::findIdentity($accessToken->user_id);
        
        if (empty($identity))
            throw new Exception('User is not found.', self::ERROR_USER_DENIED);
        
        $user->setIdentity($identity);

        return $identity;
    }

    /**
     * @inheritdoc
     */
    public function challenge($response)
    {
        $realm =  empty($this->realm) ? $this->owner->getUniqueId() : $this->realm; 
        $response->getHeaders()->set('WWW-Authenticate', "Bearer realm=\"{$realm}\"");
    }
    
    /**
     * @inheritdoc
     */
    public function handleFailure($response)
    {
        throw new Oauth2Exception('You are requesting with an invalid credential.');
    }
}
