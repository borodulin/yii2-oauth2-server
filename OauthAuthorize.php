<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use Yii;
use yii\web\Controller;
use yii\web\Response;
use conquer\oauth2\models\OauthAccessToken;
use conquer\oauth2\models\OauthClient;

/**
 * 
 * @author Andrey Borodulin
 * 
 */
class OauthAuthorize extends \yii\base\ActionFilter
{
    
    public $responseTypes = [
        'code' => 'conquer\oauth2\models\OauthAuthorizationCode',
        'token' => 'conquer\oauth2\models\OauthAccessToken',
    ];
    
    /**
     * @inheritdoc
     */
    public function beforeAction($action)
    {
        $response = \Yii::$app->response; 
        $oldFormat = $response->format;
        $response->format = Response::FORMAT_JSON;
        $this->validateAuthorizeRequest();
        $response->format = $oldFormat;
        return true;
    }

    /**
     * @inheritdoc
     */
    public function afterAction($action, $result)
    {
        if(\Yii::$app->user->isGuest)
            return $result;
        else {
            $response = \Yii::$app->response;
            $response->format = Response::FORMAT_JSON;
            
            if ($response_type == self::RESPONSE_TYPE_AUTH_CODE) {
                $result["query"]["code"] = $this->createAuthCode($client_id, $user_id, $redirect_uri, $scope);
            } elseif ($response_type == self::RESPONSE_TYPE_ACCESS_TOKEN) {
                $result["fragment"] = $this->createAccessToken($client_id, $user_id, $scope);
            }
        }
    }
    
    public function validateAuthorizeRequest()
    {
        $request = \Yii::$app->request;
        
        if(!$clientId = $request->get('client_id', $request->post('client_id')))
            throw new OauthException('No client id is supplied', 'invalid_client');

        /* @var $client  \conquer\oauth2\models\OauthClient */
        if(!$client = OauthClient::findOne(['client_id' => $clientId]))
            throw new OauthException('The client id supplied is invalid', 'invalid_client');

        if(!$redirectUri = $request->get('redirect_uri', $request->post('redirect_uri')))
            throw new OauthException('No redirect URI is supplied');

        
        // Make sure a valid redirect_uri was supplied. If specified, it must match the clientData URI.
        // @see http://tools.ietf.org/html/rfc6749#section-3.1.2
        // @see http://tools.ietf.org/html/rfc6749#section-4.1.2.1
        // @see http://tools.ietf.org/html/rfc6749#section-4.2.2.1

        if(strncasecmp($redirectUri, $client->redirect_uri, strlen($client->redirect_uri))!==0)
            throw new OauthException('The redirect URI provided is missing or does not match', 'redirect_uri_mismatch');

        $response = \Yii::$app->response;
        $response->redirect($url);
            

    }
}
