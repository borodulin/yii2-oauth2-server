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
class OauthTokenAction extends \yii\base\Action
{
    
    public $grantTypes = [
            'authorization_code' => '\conquer\oauth\models\OauthAuthorizationCode',
            'refresh_token' => '\conquer\oauth\models\OauthAuthorizationCode',
//             'client_credentials' => '\conquer\oauth\models\Oauth',
//             'password' => '\conquer\oauth\models\Oauth',
//             'urn:ietf:params:oauth:grant-type:jwt-bearer' => '',
    ];
    
    public function init()
    {
        \Yii::$app->response->format = Response::FORMAT_JSON;
    }
    
    public function run()
    {
        $request = \Yii::$app->request;
        if(!$request->isPost)
            throw new OauthException('The request method must be POST when requesting an access token');

        if (!$grantType = $request->post('grant_type'))
            throw new OauthException('The grant type was not specified in the request');

        if (!isset($this->grantTypes[$grantType]))
            throw new OauthException("Grant type \"$grantType\" is not supported", 'unsupported_grant_type');
        
        
        
        $grantClass = $this->grantTypes[$grantType];
        
        $grant = $grantClass::validateRequest();

        \Yii::$app->response->data = $grant->getResponse();        
    }
}