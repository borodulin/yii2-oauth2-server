<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use yii\web\Response;

/**
 * @author Andrey Borodulin
 * 
 */
class OauthException extends \yii\base\UserException
{
    /**
     * @var integer HTTP status code, such as 403, 404, 500, etc.
     */
    public $statusCode;

    public $name;

    /**
     * Constructor.
     * @param string $message error message
     * @param string $name error name
     * @param integer $status HTTP status code, such as 404, 500, etc.
     * @param integer $code error code
     * @param \Exception $previous The previous exception used for the exception chaining.
     */
    public function __construct($message, $name = 'invalid_request', $status = 400, $code = 0, \Exception $previous = null)
    {
        $this->statusCode = $status;
        $this->name = $name;
        parent::__construct($message, $code, $previous);
    }

    /**
     * @return string the user-friendly name of this exception
     */
    public function getName()
    {
        if(isset($this->name))
            return $this->name;
        if (isset(Response::$httpStatuses[$this->statusCode])) {
            return Response::$httpStatuses[$this->statusCode];
        } else {
            return 'Error';
        }
    }
}