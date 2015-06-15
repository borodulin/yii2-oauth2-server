<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use conquer\oauth2\models\OauthClient;
use conquer\oauth2\OauthException;

/**
 * 
 * @author Andrey Borodulin
 *
 */
trait Oauth2Trait
{
    
    const GRANT_TYPE_AUTH_CODE = 'authorization_code';
    const GRANT_TYPE_IMPLICIT = 'token';
    const GRANT_TYPE_USER_CREDENTIALS = 'password';
    const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';
    const GRANT_TYPE_REFRESH_TOKEN = 'refresh_token';
    const GRANT_TYPE_EXTENSIONS = 'extensions';
    
    
    /**
     * The request is missing a required parameter, includes an unsupported
     * parameter or parameter value, or is otherwise malformed.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INVALID_REQUEST = 'invalid_request';
    
    /**
     * The client identifier provided is invalid.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INVALID_CLIENT = 'invalid_client';
    
    /**
     * The client is not authorized to use the requested response type.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_UNAUTHORIZED_CLIENT = 'unauthorized_client';
    
    /**
     * The redirection URI provided does not match a pre-registered value.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2.4
     */
    const ERROR_REDIRECT_URI_MISMATCH = 'redirect_uri_mismatch';
    
    /**
     * The end-user or authorization server denied the request.
     * This could be returned, for example, if the resource owner decides to reject
     * access to the client at a later point.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     */
    const ERROR_USER_DENIED = 'access_denied';
    
    /**
     * The requested response type is not supported by the authorization server.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     */
    const ERROR_UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type';
    
    /**
     * The requested scope is invalid, unknown, or malformed.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     */
    const ERROR_INVALID_SCOPE = 'invalid_scope';
    
    /**
     * The provided authorization grant is invalid, expired,
     * revoked, does not match the redirection URI used in the
     * authorization request, or was issued to another client.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INVALID_GRANT = 'invalid_grant';
    
    /**
     * The authorization grant is not supported by the authorization server.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';
    
    /**
     * The request requires higher privileges than provided by the access token.
     * The resource server SHOULD respond with the HTTP 403 (Forbidden) status
     * code and MAY include the "scope" attribute with the scope necessary to
     * access the protected resource.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INSUFFICIENT_SCOPE = 'invalid_scope';
    
    /**
     * Generates an unique token.
     * @return string
     */
    protected function generateToken()
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
    protected function checkSets($requiredSet, $availableSet)
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
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-2.4.1
     * @throws OauthException
     */
    protected function validateClient()
    {
        $request = \Yii::$app->request;
        if ($clientId = $request->headers->get('PHP_AUTH_USER')) {
             $clientSecret = $request->headers->get('PHP_AUTH_PW');
        } elseif ($clientId = $request->get('client_id', $request->post('client_id'))) {
            $clientSecret = $request->get('client_secret', $request->post('client_secret'));
        } else
            throw new OauthException('Client id was not found in the headers or body', self::ERROR_INVALID_CLIENT);
        /* @var $client OauthClient */
        if (!$client = OauthClient::findOne(['client_id'=>$clientId]))
            throw new OauthException('The client was not found', self::ERROR_INVALID_CLIENT);
        
        if (!\Yii::$app->security->validatePassword($clientSecret, $client->client_secret))
            throw new OauthException('The client credentials are invalid', self::ERROR_INVALID_CLIENT);
        
        return $client;
    }
    
    /**
     * Validates redirect uri
     * @throws OauthException
     */
    protected function validateRedirectUri()
    {
        $request = \Yii::$app->request;
        
        if ($redirectUri = $request->get('redirect_uri', $request->post('redirect_uri'))) {
            // Make sure a valid redirect_uri was supplied. If specified, it must match the stored URI.
            // @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2
            // @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
            // @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
            if (strncasecmp($redirectUri, $client->redirect_uri, strlen($client->redirect_uri))!==0)
                throw new OauthException('The redirect URI provided is missing or does not match', self::ERROR_REDIRECT_URI_MISMATCH);
        }
    }
}