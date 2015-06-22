<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\responsetypes;
use conquer\oauth2\Exception;
use conquer\oauth2\RedirectException;
use conquer\oauth2\models\Client;
use conquer\oauth2\Oauth2Trait;

/**
 * 
 * @author Andrey Borodulin
 */
abstract class ResponseTypeAbstract extends \yii\base\Model
{
    use OAuth2Trait;
    
    public static $responseTypes = [
        'token' => 'conquer\oauth2\responsetypes\AccessToken',
        'code' => 'conquer\oauth2\responsetypes\AuthorizationCode',
    ];
    
    /**
     *
     * @throws Exception
     * @return ResponseTypeAbstract
     */
    public static function createResponseType(array $params = [])
    {
        $request = \Yii::$app->request;
        if(!$responseType = $request->get('response_type',$request->post('response_type')))
            throw new Exception('Invalid or missing response type');
    
        if(isset(self::$responseTypes[$responseType]))
            return \Yii::createObject(self::$responseTypes[$responseType], $params);
        else
            throw new Exception("An unsupported response type was requested.", Exception::UNSUPPORTED_RESPONSE_TYPE);
    }
    
    abstract public function getResponseData(); 
    /**
     * 
     * @throws Exception
     */
    public function finishAuthorization()
    {
        if(\Yii::$app->user->isGuest)
            throw new Exception( "The user denied access to your application", self::ERROR_USER_DENIED);
        $parts = $this->getResponseData();
        if(isset($this->state))
            $parts['query']['state'] = $this->state;
        if(isset($parts['query'])&&is_array($parts['query']))
            $parts['query'] = http_build_query($parts['query']);
        $redirectUri = http_build_url($this->redirect_uri, $parts, HTTP_URL_JOIN_QUERY);
        \Yii::$app->response->redirect($redirectUri);
    }

}