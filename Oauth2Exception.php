<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use yii\web\Response;

/**
 * @author Andrey Borodulin
 * 
 */
class Oauth2Exception extends \yii\base\UserException
{
    
    /**
     * The request is missing a required parameter, includes an unsupported
     * parameter or parameter value, or is otherwise malformed.
     *
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INVALID_REQUEST = 'invalid_request';
    
    /**
     * The client identifier provided is invalid.
     *
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INVALID_CLIENT = 'invalid_client';
    
    /**
     * The client is not authorized to use the requested response type.
     *
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_UNAUTHORIZED_CLIENT = 'unauthorized_client';
    
    /**
     * The redirection URI provided does not match a pre-registered value.
     *
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2.4
     */
    const ERROR_REDIRECT_URI_MISMATCH = 'redirect_uri_mismatch';
    
    /**
     * The end-user or authorization server denied the request.
     * This could be returned, for example, if the resource owner decides to reject
     * access to the client at a later point.
     *
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     */
    const ERROR_USER_DENIED = 'access_denied';
    
    /**
     * The requested response type is not supported by the authorization server.
     *
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     */
    const ERROR_UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type';
    
    /**
     * The requested scope is invalid, unknown, or malformed.
     *
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     */
    const ERROR_INVALID_SCOPE = 'invalid_scope';
    
    /**
     * The provided authorization grant is invalid, expired,
     * revoked, does not match the redirection URI used in the
     * authorization request, or was issued to another client.
     *
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INVALID_GRANT = 'invalid_grant';
    
    /**
     * The authorization grant is not supported by the authorization server.
     *
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';
    
    /**
     * The request requires higher privileges than provided by the access token.
     * The resource server SHOULD respond with the HTTP 403 (Forbidden) status
     * code and MAY include the "scope" attribute with the scope necessary to
     * access the protected resource.
     *
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     * @link http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INSUFFICIENT_SCOPE = 'invalid_scope';
    
    protected $name;

    
    
    /**
     * Constructor.
     * @param string $message error message
     * @param string $name error name
     * @param integer $status HTTP status code, such as 404, 500, etc.
     * @param integer $code error code
     * @param \Exception $previous The previous exception used for the exception chaining.
     */
    public function __construct($message, $name = 'invalid_request')
    {
        $this->statusCode = $status;
        $this->name = $name;
        parent::__construct($message, 0, null);
    }

    /**
     * @return string the user-friendly name of this exception
     */
    public function getName()
    {
        return isset($this->name) ? $this->name : 'Oauth2 Exception';
    }
}