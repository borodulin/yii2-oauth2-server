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
use conquer\oauth2\models\OauthRefreshToken;
use conquer\oauth2\models\OauthClient;
use conquer\oauth2\models\conquer\oauth2\models;

/**
 * 
 * @author Andrey Borodulin
 * 
 */
class Oauth2Authorize extends \yii\base\ActionFilter
{
    
    private $oldFefreshToken;
    
    public $accessTokenLifetime = 3600;
    public $refreshTokenLifetime = 1209600;
    public $authCodeLifetime = 30;
    
    // Set to true to enforce state to be passed in authorization (see http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-10.12)    
    public $enforceState = false;
    
    // Set to true to enforce redirect_uri on input for both authorize and token steps.
    public $enforceRedirect = true;
    
    public $tokenType = 'Bearer';
    
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
        
       $this->va
        
		// Make sure a valid redirect_uri was supplied. If specified, it must match the stored URI.
		// @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2
		// @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
		// @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
        if(strncasecmp($redirectUri, $client->redirect_uri, strlen($client->redirect_uri))!==0)
            throw new OauthException('The redirect URI provided is missing or does not match', 'redirect_uri_mismatch');

        // Validate state parameter exists (if configured to enforce this)
        if(!$state = $request->get('state', $request->post('state')) && $this->enforceState)
            throw new OauthRedirectException($redirectUri, "The state parameter is required.");
        
        if(!$responseType = $request->get('response_type',$request->post('response_type')))
            throw new OauthRedirectException($redirectUri, 'Invalid or missing response type.', $state);

		if (!in_array($responseType, array_keys($this->responseTypes))) 
			throw new OauthRedirectException($redirectUri, 'An unsupported response type was requested.', 'unsupported_response_type', $state);

		if(!$scope = $request->get('scope', $request->post('scope')))
		    throw new OauthRedirectException($redirectUri, 'No scope was requested.', $state, OauthException::ERROR_INVALID_SCOPE);
		
		// Validate that the requested scope is supported
		if (!$this->checkScope($scope, $client->scopes))
			throw new OAuthRedirectException($redirectUri, 'An unsupported scope was requested.', $state, OauthException::ERROR_INSUFFICIENT_SCOPE);
    }
    
    
    /**
     * Creates access token and refresh token.
     *
     * @param string $client_id  Client identifier related to the access token.
     * @param string $scope (optional) Scopes to be stored in space-separated string.
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5
     */
    protected function createAccessToken($client_id, $user_id, $scope = null) {
    
        $token = array(
            "access_token" => $this->genAccessToken(),
            "expires_in" => $this->accessTokenLifetime,
            "token_type" => $this->tokenType,
            "scope" => $scope
        );
    
        $accessToken = new OauthAccessToken();
        
        $accessToken->client_id = $client_id;
        $accessToken->user_id = $user_id;
        $accessToken->expires = time()+$this->accessTokenLifetime;
        $accessToken->scopes = $scope;
        $accessToken->save();
        
        $refreshToken = new OauthRefreshToken(); 
        $refreshToken->client_id = $client_id;
        $refreshToken->user_id = $user_id;
        $refreshToken->scopes = $scope;
        $refreshToken->expires = time() + $this->refreshTokenLifetime;
        $refreshToken->save();

        $token["refresh_token"] = $this->genAccessToken();

        // If we've granted a new refresh token, expire the old one
        if ($this->oldRefreshToken) {
            OauthRefreshToken::deleteAll(['refresh_token'=>$this->oldFefreshToken]);
            $this->oldRefreshToken = null;
        }
    
        return $token;
    }
    
}
