<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use conquer\oauth2\models\Oauth2RefreshToken;
use conquer\oauth2\models\Oauth2AccessToken;
use conquer\oauth2\models\Oauth2AuthorizationCode;
use conquer\oauth2\models\Oauth2Client;
use conquer\oauth2\models\conquer\oauth2\models;
use conquer\oauth2\Oauth2RedirectException;
use yii\web\IdentityInterface;
use yii\helpers\VarDumper;

/**
 * 
 * @author Andrey Borodulin
 *
 */
class Oauth2Server extends \yii\base\Component
{
    const GRANT_TYPE_AUTH_CODE = 'authorization_code';
    const GRANT_TYPE_IMPLICIT = 'token';
    const GRANT_TYPE_USER_CREDENTIALS = 'password';
    const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';
    const GRANT_TYPE_REFRESH_TOKEN = 'refresh_token';
    const GRANT_TYPE_EXTENSIONS = 'extensions';
    
    
    /**
     *
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-06#section-2.2
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-06#section-2.3
     */
    const TOKEN_PARAM_NAME = 'access_token';
    
    /**
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7.1
     */
    const TOKEN_TYPE_BEARER = 'Bearer';
    
    /**
     * List of possible authentication response types.
     * The "authorization_code" mechanism exclusively supports 'code'
     * and the "implicit" mechanism exclusively supports 'token'.
     *
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.1
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.1
     */
    const RESPONSE_TYPE_AUTH_CODE = 'code';
    const RESPONSE_TYPE_ACCESS_TOKEN = 'token';
    

    
    private $oldFefreshToken;
    
    public $accessTokenLifetime = 3600;
    public $refreshTokenLifetime = 1209600;
    public $authCodeLifetime = 30;
    
    public $responseTypes = [
            self::RESPONSE_TYPE_ACCESS_TOKEN,
            self::RESPONSE_TYPE_AUTH_CODE,
    ];
    
    /**
     * 
     * @var IdentityInterface
     */
    public $identityClass;
    
    
    /**
     * @var callable a PHP callable that will authenticate the user.
     * ```php
     * function ($username, $password) {
     *     return \app\models\User::findOne([
     *         'username' => $username,
     *         'password' => $password,
     *     ]);
     * }
     * ```
     * @var unknown
     */
    public $auth;
    
    /**
     * 
     * @var boolean
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-10.12
     */
    public $enforceState = false;
    
    /**
     * Generates an unique token.
     * @return string
     */
    public function generateToken()
    {
        return \Yii::$app->security->generateRandomString(40);
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
    
    /**
     * Validates the Client
     *
     * @return \conquer\oauth2\models\OauthClient
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-2.4.1
     * @throws OauthException
     */
    public function validateClient($checkCredentials = false)
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
    
    /**
     * Validates redirect uri
     *
     * @param Oauth2Client $client
     * @throws Oauth2Exception
     */
    public function validateRedirectUri($client)
    {
        $request = \Yii::$app->request;
    
        if ($redirectUri = $request->get('redirect_uri', $request->post('redirect_uri'))) {
            // Make sure a valid redirect_uri was supplied. If specified, it must match the stored URI.
            // @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2
            // @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
            // @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
            if (strncasecmp($redirectUri, $client->redirect_uri, strlen($client->redirect_uri))!==0)
                throw new Oauth2Exception('The redirect URI provided is missing or does not match', self::ERROR_REDIRECT_URI_MISMATCH);
            return $redirectUri;
        }
        return $client->redirect_uri;
    }
    
    /**
     * 
     * @throws OauthRedirectException
     * @return string|null
     */
    public function validateState($redirectUri = null)
    {
        $request = \Yii::$app->request;
        // Validate state parameter exists (if configured to enforce this)
        if(!($state = $request->get('state', $request->post('state'))) && $this->enforceState)
            if($redirectUri)
                throw new Oauth2RedirectException($redirectUri, "The state parameter is required.");
            else
                throw new Oauth2Exception("The state parameter is required.");
        return $state;        
    }
    
    public function validateResponseType($redirectUri = null)
    {
        $request = \Yii::$app->request;
        if(!$responseType = $request->get('response_type',$request->post('response_type')))
            if($redirectUri)
                throw new Oauth2RedirectException($redirectUri, 'Invalid or missing response type.', $state);
            else
                throw new Oauth2Exception($message);
        if (!in_array($responseType, $this->responseTypes))
            if($redirectUri)
                throw new Oauth2RedirectException($redirectUri, 'Invalid or missing response type.', $state);
            else
            throw new Oauth2RedirectException($redirectUri, 'An unsupported response type was requested.', 'unsupported_response_type', $state);
        return $responseType;
    }
    /**
     * 
     * @param Oauth2Client $client
     * @param string $redirectUri
     * @throws OAuth2RedirectException
     * @throws Oauth2Exception
     * @return string
     */
    public function validateScope($client, $redirectUri = null)
    {
        $request = \Yii::$app->request;
        if($scope = $request->get('scope', $request->post('scope'))){
            // Validate that the requested scope is supported
            if (!$this->checkSets($scope, $client->scopes))
                if($redirectUri)
                    throw new OAuth2RedirectException($redirectUri, 'An unsupported scope was requested.', $state, self::ERROR_INSUFFICIENT_SCOPE);
                else
                    throw new Oauth2Exception('An unsupported scope was requested.', self::ERROR_INSUFFICIENT_SCOPE);
            return $scope;
        }
        return $client->scopes;
    }
    
    /**
     * @param Oauth2Client $client
     * @throws OauthException
     * @return string
     */
    public function validateGrantType($client)
    {
        $request = \Yii::$app->request;
        
        if (!$grantType = $request->get('grant_type', $request->post('grant_type')))
            throw new OauthException('The grant type was not specified in the request');

        $identityClass = empty($this->identityClass) ? \Yii::$app->user->identityClass : $this->identityClass; 
        
        $scope = $this->validateScope($client);
        
        switch ($grantType) {
            case self::GRANT_TYPE_AUTH_CODE:
                
                if(!in_array('IdentityInterface', class_implements($identityClass)))
                    throw new OauthException("Grant type \"$grantType\" is not supported", self::ERROR_UNSUPPORTED_GRANT_TYPE);
                    
                if (!$code = $request->get('code',$request->post('code')))
                    throw new Oauth2Exception('Missing parameter. "code" is required');
        
                $this->validateRedirectUri($client);
        
                // Check the code exists
                if(!$authCode = Oauth2AuthorizationCode::findOne(['authorization_code'=>$code]))
                    throw new Oauth2Exception("Refresh token doesn't exist or is invalid for the client", Oauth2Server::ERROR_INVALID_GRANT);
                
                if ($authCode->expires < time())
                    throw new OAuth2Exception("The authorization code has expired", Oauth2Server::ERROR_INVALID_GRANT);
                
                if(!$identity = $identityClass::findIdentity($authCode->user_id))
                    throw new Oauth2Exception('User is not found', self::ERROR_USER_DENIED);
                
                \Yii::$app->user->setIdentity($identity);
                
                
                break;
                	
            case self::GRANT_TYPE_USER_CREDENTIALS:
                        
                $username = $request->get('username',$request->post('username'));
                $password = $request->get('password', $request->post('password'));
                if (!$username || !$password)
                    throw new OAuth2Exception('Missing parameters. "username" and "password" required');

                if ($this->auth) {
                    $identity = call_user_func($this->auth, $username, $password);
                    if(!$identity instanceof IdentityInterface)
                        throw new OauthException("Grant type \"$grantType\" is not supported", self::ERROR_UNSUPPORTED_GRANT_TYPE);
                    
                    \Yii::$app->user->setIdentity($identity);
                } else
                    throw new OauthException("Grant type \"$grantType\" is not supported", self::ERROR_UNSUPPORTED_GRANT_TYPE); 

                break;
                	
            case self::GRANT_TYPE_CLIENT_CREDENTIALS:
                throw new OAuth2Exception('This functionality is not implemented yet.', 'not_implemented');
                
                $this->validateClient();
                
                break;
                	
            case self::GRANT_TYPE_REFRESH_TOKEN:
                
                if(!in_array('IdentityInterface', class_implements($identityClass)))
                    throw new OauthException("Grant type \"$grantType\" is not supported", self::ERROR_UNSUPPORTED_GRANT_TYPE);
                
                if(!$token = $request->get('refresh_token', $request->post('refresh_token')))
                    throw new OAuth2Exception('No "refresh_token" parameter found');

                if(!$refreshToken = Oauth2RefreshToken::findOne(['refresh_token'=>$token]))
                    throw new OAuth2Exception('Invalid refresh token', self::ERROR_INVALID_GRANT);
        
                
                if ($refreshToken->expires < time())
                    throw new OAuth2Exception('Refresh token has expired', self::ERROR_INVALID_GRANT);
        
                // store the refresh token locally so we can delete it when a new refresh token is generated
                $this->oldRefreshToken = $refreshToken->refresh_token;
                
                if(!$identity = $identityClass::findIdentity($refreshToken->user_id))
                    throw new Oauth2Exception('User is not found', self::ERROR_USER_DENIED);
                
                \Yii::$app->user->setIdentity($identity);

                break;
                	
            case self::GRANT_TYPE_IMPLICIT:
                /* TODO: NOT YET IMPLEMENTED */
                throw new OAuth2Exception('This functionality is not implemented yet.', 'not_implemented');
        
                break;
                
            default :
                throw new OauthException("Grant type \"$grantType\" is not supported", self::ERROR_UNSUPPORTED_GRANT_TYPE);
        }
        
        if(!$this->checkSets($grantType, $client->grant_types))
            throw new OauthException('The grant type is unauthorized for this client_id', self::ERROR_UNAUTHORIZED_CLIENT);
                
        return  [
            'access_token' => $this->createAccessToken($client->client_id, \Yii::$app->user->id),
            'expires_in' => $this->accessTokenLifetime,
            'token_type' => self::RESPONSE_TYPE_ACCESS_TOKEN,
            'scope' => $scope,
            'refresh_token' => $this->createRefreshToken($client->client_id, \Yii::$app->user->id),
        ];
    }
    
    public function validateAuthorizeRequest()
    {
        $request = \Yii::$app->request;
    
        $client = $this->validateClient();
    
        $redirectUri =  $this->validateRedirectUri($client);
    
        $this->validateState();
        
        $this->validateResponseType();
        
        $this->validateScope($client, $redirectUri);
    }
    
    public function finishAuthorization()
    {
        $client = $this->validateClient();
        $redirectUri = $this->validateRedirectUri($client);
        $state = $this->validateState();
        $scope = $this->validateScope($client, $redirectUri);
        $user = \Yii::$app->user;
        if($user->isGuest)
            throw new Oauth2RedirectException($redirectUri, "The user denied access to your application", $state, self::ERROR_USER_DENIED);
        
        $responseType = $this->validateResponseType($redirectUri);
        switch ($responseType){
            case self::RESPONSE_TYPE_ACCESS_TOKEN:
                $parts["fragment"] = $this->createAccessToken($client->client_id, $user->id, $scope);
                $parts["query"] = http_build_query(["state"=> $state]);
                break;
            case self::RESPONSE_TYPE_AUTH_CODE:
                $query["code"] = $this->createAuthorizationCode($client->client_id, $user->id, $redirectUri, $scope);
                if($state)
                    $query["state"] = $state;
                $parts['query'] = http_build_query($query);
                break;
        }
        $redirectUri = http_build_url($redirectUri, $parts, HTTP_URL_JOIN_QUERY);
        \Yii::$app->response->redirect($redirectUri);
    }
    
    /**
     * As per the Bearer spec (draft 8, section 2) - there are three ways for a client
     * to specify the bearer token, in order of preference: Authorization Header,
     * POST and GET.
     * 
     * @return Oauth2AccessToken
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2
     * Old Android version bug (at least with version 2.2)
     * @link http://code.google.com/p/android/issues/detail?id=6684
     *
     */
    public function validateBearerToken() {
    
        $request = \Yii::$app->request;
        
        $authHeader = $request->getHeaders()->get('Authorization');
    
        $postToken = $request->post(self::TOKEN_TYPE_BEARER);
        $getToken = $request->get(self::TOKEN_TYPE_BEARER);
    
        // Check that exactly one method was used
        $methodsUsed = isset($authHeader) + isset($postToken) + isset($getToken);
        if ($methodsUsed > 1) {
            throw new Oauth2Exception('Only one method may be used to authenticate at a time (Auth header, POST or GET).');
        } elseif ($methodsUsed == 0) {
            throw new Oauth2Exception('The access token was not found.');
        }
    
        // HEADER: Get the access token from the header
        if ($authHeader) {
            if (preg_match("/^Bearer\\s+(.*?)$/", $authHeader, $matches)) 
                $token = $matches[1];
            else
                throw new Oauth2Exception('Malformed auth header.');
        } else {
            // POST: Get the token from POST data
            if ($postToken) {
                if(!$request->isPost)
                    throw new OauthException('When putting the token in the body, the method must be POST.');
        
                // IETF specifies content-type. NB: Not all webservers populate this _SERVER variable
                if($request->contentType != 'application/x-www-form-urlencoded')
                    throw new Oauth2Exception('The content type for POST requests must be "application/x-www-form-urlencoded"');
        
                $token = $postToken;
            } else 
                $token = $getToken;
        }
        
        $accessToken = Oauth2AccessToken::find()
            ->with('client')
            ->where(['access_token'=>$token])
            ->One();
        
        if(empty($accessToken))
            throw new Oauth2Exception('The access token provided is invalid.', self::ERROR_INVALID_GRANT);
            
        if($accessToken->expires < time())
            throw new OAuth2Exception('The access token provided has expired.', self::ERROR_INVALID_GRANT);
        
        $this->validateScope($accessToken->client);
            
        return $accessToken;
    }
    
    public function authorizeUser($userId)
    {
        $identity = $this->identity->findIdentity($userId);
        
        
        
        if (empty($identity))
            throw new Oauth2Exception('User is not found', self::ERROR_USER_DENIED);
        \Yii::$app->user->switchIdentity($identity);
    }
    
    /**
     * Creates access token
     *
     * @param string $clientId
     * @param string $scope (optional)
     * @return string
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5
     */
    public function createAccessToken($clientId, $userId, $scope = null)
    {

        
        $accessToken = new Oauth2AccessToken();
        $accessToken->access_token = $this->generateToken();
        $accessToken->client_id = $clientId;
        $accessToken->user_id = $userId;
        $accessToken->expires = time() + $this->accessTokenLifetime;
        $accessToken->scopes = $scope;
        $accessToken->save();
        return $accessToken->access_token;
    
    
//         $token["refresh_token"] = $this->genAccessToken();
    
//         // If we've granted a new refresh token, expire the old one
//         if ($this->oldRefreshToken) {
//             OauthRefreshToken::deleteAll(['refresh_token'=>$this->oldFefreshToken]);
//             $this->oldRefreshToken = null;
//         }
    }
    
    /**
     * 
     * @param string $clientId
     * @param integer $userId
     * @param string $scope
     * @return string
     */
    public function createRefreshToken($clientId, $userId, $scope = null)
    {
        $refreshToken = new Oauth2RefreshToken();
        $refreshToken->refresh_token = $this->generateToken();
        $refreshToken->client_id = $clientId;
        $refreshToken->user_id = $userId;
        $refreshToken->scopes = $scope;
        $refreshToken->expires = time() + $this->refreshTokenLifetime;
        $refreshToken->save();
        if($this->oldFefreshToken)
            Oauth2RefreshToken::deleteAll(['refresh_token'=>$this->oldFefreshToken]);
        return $refreshToken->refresh_token;
    }
    
    /**
     * 
     * @param string $clientId
     * @param integer $userId
     * @param string $scope
     * @return string
     */
    public function createAuthorizationCode($clientId, $userId, $redirectUri, $scope = null)
    {
        $authorizationCode = new Oauth2AuthorizationCode();
        $authorizationCode->authorization_code = $this->generateToken();
        $authorizationCode->client_id = $clientId;
        $authorizationCode->user_id = $userId;
        $authorizationCode->redirect_uri = $redirectUri;
        $authorizationCode->scopes = $scope;
        $authorizationCode->expires = time() + $this->authCodeLifetime;
        if($authorizationCode->save())
            return $authorizationCode->authorization_code;
        else
            throw new Oauth2Exception(VarDumper::dumpAsString($authorizationCode->errors),'system_error');
    }
}