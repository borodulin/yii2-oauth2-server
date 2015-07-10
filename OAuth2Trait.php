<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use conquer\oauth2\models\Client;
use conquer\oauth2\Exception;
use conquer\oauth2\models\AuthorizationCode;
use conquer\oauth2\models\AccessToken;
use conquer\oauth2\models\RefreshToken;

/**
 * 
 * @author Andrey Borodulin
 *
 */
trait OAuth2Trait
{
    private $_client;
    private $_authCode;
    private $_refreshToken;
    private $_bearerToken;
    
    public $accessTokenLifetime = 3600;
    public $refreshTokenLifetime = 1209600;
    public $authCodeLifetime = 30;
    
    public function addError($attribute, $error="")
    {
        throw new Exception($error, Exception::INVALID_REQUEST);
    }
    
    public function getGrant_type()
    {
        $request = \Yii::$app->request;
        return $request->post('grant_type', $request->get('grant_type'));
    }
    
    public function getClient_id()
    {
        $request = \Yii::$app->request;    
        if (!$clientId = $request->headers->get('PHP_AUTH_USER'))
            $clientId = $request->post('client_id', $request->get('client_id'));
        return $clientId;
    }
    
    public function getClient_secret()
    {
        $request = \Yii::$app->request;
        if(!$clientSecret = $request->headers->get('PHP_AUTH_PW'))
            $clientSecret = $request->post('client_secret', $request->get('client_secret'));
        return $clientSecret;
    }
    
    public function getRedirect_uri()
    {
        $request = \Yii::$app->request;
        return $request->post('redirect_uri', $request->get('redirect_uri'));
    }
    
    public function getScope()
    {
        $request = \Yii::$app->request;
        return $request->post('scope', $request->get('scope'));
    }
    
    public function getState()
    {
        $request = \Yii::$app->request;
        return $request->post('state', $request->get('state'));
    }
    
    public function getResponse_type()
    {
        $request = \Yii::$app->request;
        return $request->post('response_type',$request->get('response_type'));
    }
    
    public function getCode()
    {
        $request = \Yii::$app->request;
        return $request->post('code',$request->get('code'));
    }
    
    public function getRefresh_token()
    {
        $request = \Yii::$app->request;
        return $request->post('refresh_token',$request->get('refresh_token'));
    }
    
    /**
     *
     * @return \conquer\oauth2\models\Client
     */
    public function getClient()
    {
        if(is_null($this->_client)){
            if(!$this->_client = Client::findOne(['client_id' => $this->getClient_id()]))
                throw new Exception('The client credentials are invalid', Exception::INVALID_CLIENT);
        }
        return $this->_client;
    }
    
    /**
     *
     * @return \conquer\oauth2\models\AuthorizationCode
     */
    public function getAuthCode()
    {
        if(is_null($this->_authCode)){
            if(!$this->_authCode = AuthorizationCode::findOne(['authorization_code' => $this->getCode()]))
                throw new Exception('The Authorization code is invalid');
        }
        return $this->_authCode;
    }
    
    /**
     *
     * @return \conquer\oauth2\models\RefreshToken
     */
    public function getRefreshToken()
    {
        if(is_null($this->_refreshToken)){
            if(!$this->_refreshToken = RefreshToken::findOne(['refresh_token' => $this->getRefresh_token()]))
                throw new Exception('The Refresh Token is invalid');
        }
        return $this->_refreshToken;
    }
    
    public function validateClient_id($attribute, $params)
    {
        $this->getClient();
    }
    
    public function validateClient_secret($attribute, $params)
    {
        if(empty($this->client) || !\Yii::$app->security->compareString($this->client->client_secret, $this->$attribute))
            $this->addError($attribute, 'The client credentials are invalid', Exception::INVALID_CLIENT);
    }
    
    public function validateRedirect_uri($attribute, $params)
    {
        if(empty($this->$attribute))
            $this->$attribute = $this->client->redirect_uri;
        elseif (strncasecmp($this->$attribute, $this->client->redirect_uri, strlen($this->client->redirect_uri))!==0)
            $this->addError($attribute, 'The redirect URI provided is missing or does not match', Exception::REDIRECT_URI_MISMATCH);
    }
    
    public function validateRefresh_token($attribute, $params)
    {
        if(empty($this->$attribute))
            $this->addError($attribute, 'The Refresh token is missing');
        $this->getRefreshToken();
    }
    
    /**
     *
     */
    public function validateScope($attribute, $params)
    {
        if (!$this->checkSets($this->$attribute, $this->client->scopes))
//             if(isset($this->redirect_uri))
//                 throw new RedirectException($this->redirect_uri, 'An unsupported scope was requested.', Exception::INSUFFICIENT_SCOPE);
//             else
                $this->addError($attribute, 'An unsupported scope was requested.', Exception::INSUFFICIENT_SCOPE);
    }
    
    public function validateCode($attribute, $params)
    {
        if(!$this->getCode())
            $this->addError($attribute, 'The Authorization Code is invalid');
        $this->getAuthCode();
    }
    
    /**
     * Checks if everything in required set is contained in available set.
     *
     * @param string|array $requiredSet
     * @param string|array $availableSet
     * @return boolean
     */
    public function checkSets($requiredSet, $availableSet)
    {
        if (!is_array($requiredSet))
            $requiredSet = explode(' ', trim($requiredSet));
    
        if (!is_array($availableSet))
            $availableSet = explode(' ', trim($availableSet));
    
        return (count(array_diff($requiredSet, $availableSet)) == 0);
    }
}