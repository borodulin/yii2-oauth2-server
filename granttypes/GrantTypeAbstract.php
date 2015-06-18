<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

/**
 * 
 * @author Andrey Borodulin
 *
 */
class GrantTypeAbstract extends \yii\base\Model
{
    public function addError($attribute, $error, $params = [], $errorType = 'invalid_request')
    {
        throw new Oauth2Exception(\Yii::t('app', $error, $params), $errorType);
    }
    
    protected function getClient()
    {
        if(empty($this->_client))
            $this->_client = Client::findOne($this->client_id);
        return $this->_client;
    }
    
    public function validateClient($attribute, $params)
    {
            $request = \Yii::$app->request;
            if ($clientId = $request->headers->get('PHP_AUTH_USER')) {
                $clientSecret = $request->headers->get('PHP_AUTH_PW');
            } elseif ($clientId = $request->get('client_id', $request->post('client_id'))) {
                $clientSecret = $request->get('client_secret', $request->post('client_secret'));
            } else
                throw new Oauth2Exception('Client id was not found in the headers or body', self::ERROR_INVALID_CLIENT);
            /* @var $client Oauth2Client */
            if (!$client = Oauth2Client::findOne(['client_id'=>$clientId]))
                throw new Oauth2Exception('The client was not found', self::ERROR_INVALID_CLIENT);
        
            if($checkCredentials && !\Yii::$app->security->validatePassword($clientSecret, $client->client_secret))
                throw new Oauth2Exception('The client credentials are invalid', self::ERROR_INVALID_CLIENT);
        
            return $client;
    }
    
    public function validateClientSecret($attribute, $params)
    {
        $client = $this->getClient();
        if(!\Yii::$app->security->validatePassword($this->$attribute, $client->client_secret))
            $this->addError($attribute, 'The client credentials are invalid');
    }
    
    public function validateRedirectUri($attributes, $params)
    {
        // Make sure a valid redirect_uri was supplied. If specified, it must match the stored URI.
        // @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2
        // @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
        // @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
        if (strncasecmp($redirectUri, $client->redirect_uri, strlen($client->redirect_uri))!==0)
            throw new Oauth2Exception('The redirect URI provided is missing or does not match', self::ERROR_REDIRECT_URI_MISMATCH);
            return $redirectUri;
            
        return $client->redirect_uri;
    }
}