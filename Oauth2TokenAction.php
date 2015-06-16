<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use yii\web\Response;
use conquer\oauth2\models\OauthAuthorizationCode;

/**
 * 
 * @author Andrey Borodulin
 *
 */
class Oauth2TokenAction extends \yii\base\Action
{
    public function init()
    {
        \Yii::$app->response->format = Response::FORMAT_JSON;
    }
    
    public function run()
    {
        $request = \Yii::$app->request;

        /* @var $oauth2Server Oauth2Server */
        $oauth2Server = \Yii::createObject(Oauth2Server::className());
        
        $grantType = $oauth2Server->validateGrantType();
        
        $client = $oauth2Server->validateClient();
        
        $scope = $oauth2Server->validateScope($client);
        
        \Yii::$app->response->data = $oauth2Server->validateGrantType($client);
    }
}