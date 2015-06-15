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
    use OauthTrait;

    public $wwwRealm = 'Service';
    
    public $grantTypes = [
            'code' => '\conquer\oauth\models\OauthAuthorizationCode',
            'token' => '\conquer\oauth\models\OauthRefreshToken',
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

//         if(!$request->isPost)
//             throw new OauthException('The request method must be POST when requesting an access token');
        
        if (!$grantType = $request->get('grant_type', $request->post('grant_type')))
            throw new OauthException('The grant type was not specified in the request');
        
        if (!isset($this->grantTypes[$grantType]))
            throw new OauthException("Grant type \"$grantType\" is not supported", 'unsupported_grant_type');
        
        $client = $this->validateClient();
        
        if(!$this->checkSets($grantType, $client->grant_types))
            throw new OauthException('The grant type is unauthorized for this client_id', OauthException::ERROR_UNAUTHORIZED_CLIENT);
        
        // Do the granting
        switch ($grantType) {
            case self::GRANT_TYPE_AUTH_CODE:
                if (!$code = $request->get('code',$request->post('code')))
                    throw new OauthException('Missing parameter. "code" is required');
        
                if ($this->getVariable(self::CONFIG_ENFORCE_INPUT_REDIRECT) && !$input["redirect_uri"]) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_REQUEST, "The redirect URI parameter is required.");
                }
        
                // Check the code exists
                if(!$authCode = OauthAuthorizationCode::findOne(['authorization_code'=>$code]))
                    throw new OauthException("Refresh token doesn't exist or is invalid for the client", self::ERROR_INVALID_GRANT);
                
                // Validate the redirect URI. If a redirect URI has been provided on input, it must be validated
                if ($input["redirect_uri"] && !$this->validateRedirectUri($input["redirect_uri"], $stored["redirect_uri"])) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_REDIRECT_URI_MISMATCH, "The redirect URI is missing or do not match");
                }
        
                if ($authCode->expires < time())
                    throw new OAuthException("The authorization code has expired", self::ERROR_INVALID_GRANT);

                break;
                	
            case self::GRANT_TYPE_USER_CREDENTIALS:
                if (!($this->storage instanceof IOAuth2GrantUser)) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_UNSUPPORTED_GRANT_TYPE);
                }
        
                if (!$input["username"] || !$input["password"]) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_REQUEST, 'Missing parameters. "username" and "password" required');
                }
        
                $stored = $this->storage->checkUserCredentials($client[0], $input["username"], $input["password"]);
        
                if ($stored === FALSE) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_GRANT);
                }
                break;
                	
            case self::GRANT_TYPE_CLIENT_CREDENTIALS:
                if (!($this->storage instanceof IOAuth2GrantClient)) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_UNSUPPORTED_GRANT_TYPE);
                }
        
                if (empty($client[1])) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_CLIENT, 'The client_secret is mandatory for the "client_credentials" grant type');
                }
                // NB: We don't need to check for $stored==false, because it was checked above already
                $stored = $this->storage->checkClientCredentialsGrant($client[0], $client[1]);
                break;
                	
            case self::GRANT_TYPE_REFRESH_TOKEN:
                if (!($this->storage instanceof IOAuth2RefreshTokens)) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_UNSUPPORTED_GRANT_TYPE);
                }
        
                if (!$input["refresh_token"]) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_REQUEST, 'No "refresh_token" parameter found');
                }
        
                $stored = $this->storage->getRefreshToken($input["refresh_token"]);
        
                if ($stored === NULL || $client[0] != $stored["client_id"]) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_GRANT, 'Invalid refresh token');
                }
        
                if ($stored["expires"] < time()) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_GRANT, 'Refresh token has expired');
                }
        
                // store the refresh token locally so we can delete it when a new refresh token is generated
                $this->oldRefreshToken = $stored["refresh_token"];
                break;
                	
            case self::GRANT_TYPE_IMPLICIT:
                /* TODO: NOT YET IMPLEMENTED */
                throw new OAuth2ServerException('501 Not Implemented', 'This OAuth2 library is not yet complete. This functionality is not implemented yet.');
                if (!($this->storage instanceof IOAuth2GrantImplicit)) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_UNSUPPORTED_GRANT_TYPE);
                }
        
                break;
                	
                // Extended grant types:
            case filter_var($input["grant_type"], FILTER_VALIDATE_URL):
                if (!($this->storage instanceof IOAuth2GrantExtension)) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_UNSUPPORTED_GRANT_TYPE);
                }
                $uri = filter_var($input["grant_type"], FILTER_VALIDATE_URL);
                $stored = $this->storage->checkGrantExtension($uri, $inputData, $authHeaders);
        
                if ($stored === FALSE) {
                    throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_GRANT);
                }
                break;
                	
            default :
                throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_REQUEST, 'Invalid grant_type parameter or parameter missing');
        }
        
        if (!isset($stored["scope"])) {
            $stored["scope"] = NULL;
        }
        
        // Check scope, if provided
        if ($input["scope"] && (!is_array($stored) || !isset($stored["scope"]) || !$this->checkScope($input["scope"], $stored["scope"]))) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_INVALID_SCOPE, 'An unsupported scope was requested.');
        }
        
        $user_id = isset($stored['user_id']) ? $stored['user_id'] : null;
        $token = $this->createAccessToken($client[0], $user_id, $stored['scope']);
        
        // Send response
        $this->sendJsonHeaders();
        echo json_encode($token);
        
        
        
        
        
        
        
        
        $grantClass = $this->grantTypes[$grantType];
        
        $grant = $grantClass::validateRequest();

        \Yii::$app->response->data = $grant->getResponse();        
    }
}