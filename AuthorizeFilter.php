<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use yii\web\Response;
use yii\web\Session;
use conquer\oauth2\responsetypes\ResponseTypeAbstract;

/**
 * 
 * @author Andrey Borodulin
 * 
 */
class AuthorizeFilter extends \yii\base\ActionFilter
{

    private $_responseType;

    private $_storeKey = 'ear6kme7or19rnfldtmwsxgzxsrmngqw';
    
    public $authCodeLifetime = 30;
    public $accessTokenLifetime = 3600;
    public $refreshTokenLifetime = 1209600;
    
    /**
     * @inheritdoc
     */
    public function beforeAction($action)
    {   
        $this->_responseType = ResponseTypeAbstract::createResponseType([
            'authCodeLifetime' => $this->authCodeLifetime,
            'accessTokenLifetime' => $this->accessTokenLifetime,
            'refreshTokenLifetime' => $this->refreshTokenLifetime,                
        ]);
        
        $this->_responseType->validate();

        \Yii::$app->session->set($this->_storeKey, serialize($this->_responseType));
        
        return true;
    }

    /**
     * @inheritdoc
     */
    public function afterAction($action, $result)
    {
        if(\Yii::$app->user->isGuest)
            return $result;
        else 
            $this->finishAuthorization();
    }
    
    /**
     * @throws Exception
     * @return \conquer\oauth2\responsetypes\ResponseTypeAbstract
     */
    public function getResponseType()
    {
        if (empty($this->_responseType)) {
            if (\Yii::$app->session->has($this->_storeKey))
                $this->_responseType = unserialize(\Yii::$app->session->get($this->_storeKey));
            else
                throw new Exception('Invalid server state or the User Session has expired', Exception::SERVER_ERROR);
        }
        return $this->_responseType;
    }
    
    public function finishAuthorization()
    {
        $responseType = $this->getResponseType();
        if (\Yii::$app->user->isGuest)
            $responeType->errorRedirect('The user denied access to your application', Exception::ACCESS_DENIED);
        
        $parts = $responseType->getResponseData();
        
        $redirectUri = http_build_url($responseType->redirect_uri, $parts, HTTP_URL_JOIN_QUERY);
        
        \Yii::$app->response->redirect($redirectUri);
    }
    
}
