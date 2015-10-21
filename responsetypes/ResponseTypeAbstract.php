<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\responsetypes;
use conquer\oauth2\Exception;
use conquer\oauth2\OAuth2Trait;
use yii\helpers\ArrayHelper;

/**
 * 
 * @author Andrey Borodulin
 */
abstract class ResponseTypeAbstract extends \yii\base\Model
{
    use OAuth2Trait;
    
    public static $responseTypes = [
        'token' => 'conquer\oauth2\responsetypes\Implicit',
        'code' => 'conquer\oauth2\responsetypes\Authorization',
    ];
    
    abstract function getResponseData();
    
    public function __sleep()
    {
        return ArrayHelper::merge($this->safeAttributes(),[
            'authCodeLifetime',
            'accessTokenLifetime',
        ]);
    }
    
    /**
     *
     * @throws Exception
     * @return ResponseTypeAbstract
     */
    public static function createResponseType(array $params = [])
    {
        if (!$responseType = self::getRequestValue('response_type')) {
            throw new Exception('Invalid or missing response type');
        }
        if (isset(self::$responseTypes[$responseType])) {
            return \Yii::createObject(self::$responseTypes[$responseType], $params);
        } else {
            throw new Exception("An unsupported response type was requested.", Exception::UNSUPPORTED_RESPONSE_TYPE);
        }
    }

}