<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;
use conquer\oauth2\Exception;
use conquer\oauth2\RedirectException;
use conquer\oauth2\models\Client;
use conquer\oauth2\OAuth2Trait;

/**
 * @author Andrey Borodulin
 */
abstract class GrantTypeAbstract extends \yii\base\Model
{
    use OAuth2Trait;
    
    public static $grantTypes = [
        'authorization_code' => 'conquer\oauth2\granttypes\AuthorizationCode',
        'client_credentials' => 'conquer\oauth2\granttypes\ClientCredentials',
        'password' => 'conquer\oauth2\granttypes\UserCredentials',
        'refresh_token' => 'conquer\oauth2\granttypes\RefreshToken',
        'token' => 'conquer\oauth2\granttypes\Implicit',
        'urn:ietf:params:oauth:grant-type:jwt-bearer' => 'conquer\oauth2\granttypes\JwtBearer',
    ];

    /**
     * 
     */
    abstract public function getResponseData();
    
    /**
     * 
     * @throws Exception
     * @return GrantTypeAbstract
     */
    public static function createGrantType(array $params = [])
    {
        $request = \Yii::$app->request;
        
        if (!$grantType = $request->get('grant_type', $request->post('grant_type')))
            throw new Exception('The grant type was not specified in the request');
        
        if(isset(self::$grantTypes[$grantType]))
            return \Yii::createObject(self::$grantTypes[$grantType], $params);
        else
            throw new Exception("An unsupported grant type was requested", Exception::UNSUPPORTED_GRANT_TYPE);
    }
    
    
    
   
    
}