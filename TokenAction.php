<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use yii\web\Response;
use conquer\oauth2\models\OauthAuthorizationCode;
use conquer\oauth2\granttypes\GrantTypeAbstract;
use yii\validators\Validator;

/**
 * 
 * @author Andrey Borodulin
 *
 */
class TokenAction extends \yii\base\Action
{
    
    public $accessTokenLifetime = 3600;
    public $refreshTokenLifetime = 1209600;
    
    public function init()
    {
        \Yii::$app->response->format = Response::FORMAT_JSON;
        $this->controller->enableCsrfValidation = false;
    }
    
    public function run()
    {
        $request = \Yii::$app->request;
        
        $grantType = GrantTypeAbstract::createGrantType([
                'accessTokenLifetime' => $this->accessTokenLifetime,
                'refreshTokenLifetime' => $this->refreshTokenLifetime,
        ]);
        
        $grantType->validate();
        
        \Yii::$app->response->data = $grantType->getResponseData();
                
    }
}