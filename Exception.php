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
class Exception extends \yii\base\UserException
{
    
    const INVALID_REQUEST = 'invalid_request';
    const INVALID_CLIENT = 'invalid_client';
    const UNAUTHORIZED_CLIENT = 'unauthorized_client';
    const REDIRECT_URI_MISMATCH = 'redirect_uri_mismatch';
    const USER_DENIED = 'access_denied';
    const UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type';
    const INVALID_SCOPE = 'invalid_scope';
    const INVALID_GRANT = 'invalid_grant';
    const UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';
    const INSUFFICIENT_SCOPE = 'invalid_scope';
    const NOT_IMPLEMENTED = 'not_implemented';
    const INTERNAL_ERROR = 'internal_error';
        
    protected $error;

    
    
    /**
     * Constructor.
     * @param string $error_description (optional)
     * @param string $error A single error code
     * @param string $name error name
     */
    public function __construct($error_description = null, $error = 'invalid_request')
    {
        $this->error = $error;
        parent::__construct($error_description, 0, null);
    }

    /**
     * @return string the user-friendly name of this exception
     */
    public function getName()
    {
        return isset($this->error) ? $this->error : 'OAuth Exception';
    }
}
