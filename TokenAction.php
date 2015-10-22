<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use yii\web\Response;

/**
 * 
 * @author Andrey Borodulin
 *
 */
class TokenAction extends \yii\base\Action
{
    
    public $grantTypes = [
            'authorization_code' => 'conquer\oauth2\granttypes\Authorization',
            'refresh_token' => 'conquer\oauth2\granttypes\RefreshToken',
//         'client_credentials' => 'conquer\oauth2\granttypes\ClientCredentials',
//         'password' => 'conquer\oauth2\granttypes\UserCredentials',
//         'urn:ietf:params:oauth:grant-type:jwt-bearer' => 'conquer\oauth2\granttypes\JwtBearer',
    ];
    
    public function init()
    {
        \Yii::$app->response->format = Response::FORMAT_JSON;
        $this->controller->enableCsrfValidation = false;
    }
    
    public function run()
    {
        if (!$grantType = BaseModel::getRequestValue('grant_type')) {
            throw new Exception('The grant type was not specified in the request');
        }
        if (isset($this->grantTypes[$grantType])) {
            $grantModel = \Yii::createObject($this->grantTypes[$grantType]);
        } else {
            throw new Exception("An unsupported grant type was requested", Exception::UNSUPPORTED_GRANT_TYPE);
        }
        
        $grantModel->validate();
        
        \Yii::$app->response->data = $grantModel->getResponseData();
    }
}