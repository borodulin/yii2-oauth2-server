<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use conquer\oauth2\models\Client;
use conquer\oauth2\Exception;
use conquer\oauth2\RedirectException;
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
    
    public $accessTokenLifetime = 3600;
    public $refreshTokenLifetime = 1209600;
    
    public function init()
    {
        foreach ($this->safeAttributes() as $name) {
            $this->$name = $this->{'get'.$name}();
        }
    }

    public function addError($attribute, $error="")
    {
        throw new Exception($error, Exception::INVALID_REQUEST);
    }
    
    public function errorServer($error, $type = Exception::INVALID_REQUEST)
    {
        throw new Exception($error, Exception::INVALID_REQUEST);
    }
    
    public function errorRedirect($error, $type = Exception::INVALID_REQUEST)
    {
        $redirectUri = isset($this->redirect_uri) ? $this->redirect_uri : $this->getClient()->redirect_uri;
        if ($redirectUri)
            throw new RedirectException($redirectUri, $error, $type, isset($this->state)?$this->state:null);
        else
            throw new Exception($error, $type);
    }
    
    public static function getRequestValue($param, $header = null)
    {
        static $request;
        if (is_null($request))
            $request = \Yii::$app->request;
        if ($header && ($result = $request->headers->get($header)))
            return $result;
        else
            return $request->post($param, $request->get($param));
    }
    
    public function getGrant_type()
    {
        return $this->getRequestValue('grant_type');
    }
    
    public function getClient_id()
    {
        return $this->getRequestValue('client_id', 'PHP_AUTH_USER');
    }
    
    public function getClient_secret()
    {
        return $this->getRequestValue('client_secret', 'PHP_AUTH_PW');
    }
    
    public function getRedirect_uri()
    {
        return $this->getRequestValue('redirect_uri');
    }
    
    public function getScope()
    {
        return $this->getRequestValue('scope');
    }
    
    public function getState()
    {
        return $this->getRequestValue('state');
    }
    
    public function getResponse_type()
    {
        return $this->getRequestValue('response_type');
    }
    
    /**
     *
     * @return \conquer\oauth2\models\Client
     */
    public function getClient()
    {
        if (is_null($this->_client)) {
            if (empty($this->client_id))
                $this->errorServer('Unknown client', Exception::INVALID_CLIENT);
            if (!$this->_client = Client::findOne(['client_id' => $this->client_id]))
                $this->errorServer('Unknown client', Exception::INVALID_CLIENT);
        }
        return $this->_client;
    }
    
    public function validateClient_id($attribute, $params)
    {
        $this->getClient();
    }
    
    public function validateClient_secret($attribute, $params)
    {
        if (!\Yii::$app->security->compareString($this->getClient()->client_secret, $this->$attribute))
            $this->addError($attribute, 'The client credentials are invalid', Exception::UNAUTHORIZED_CLIENT);
    }
    
    public function validateRedirect_uri($attribute, $params)
    {
        if (!empty($this->$attribute)){
            $clientRedirectUri = $this->getClient()->redirect_uri;
            if (strncasecmp($this->$attribute, $clientRedirectUri, strlen($clientRedirectUri))!==0)
                $this->errorServer('The redirect URI provided is missing or does not match', Exception::REDIRECT_URI_MISMATCH);
        }
    }
    
    public function validateScope($attribute, $params)
    {
        if (!$this->checkSets($this->$attribute, $this->client->scopes))
            $this->errorRedirect('The requested scope is invalid, unknown, or malformed.', Exception::INVALID_SCOPE);
    }
    
    public function validateCode($attribute, $params)
    {
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