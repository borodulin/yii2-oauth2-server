<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use yii\web\Response;
use conquer\oauth2\Oauth2Server;

/**
 * 
 * @author Andrey Borodulin
 * 
 */
class AuthorizeFilter extends \yii\base\ActionFilter
{

    private $_oauth2Server;

    public $authCodeLifetime = 30;
    
    /**
     * @inheritdoc
     */
    public function beforeAction($action)
    {
//         $response = \Yii::$app->response; 
//         $oldFormat = $response->format;
//         $response->format = Response::FORMAT_JSON;
        
        $oauth2Server = $this->getOauth2Server();
        $oauth2Server->validateAuthorizeRequest();
        
//         $response->format = $oldFormat;
        return true;
    }

    /**
     * @inheritdoc
     */
    public function afterAction($action, $result)
    {
        if(\Yii::$app->user->isGuest)
            return $result;
        else {
            $oauth2Server = $this->getOauth2Server();
            $oauth2Server->finishAuthorization();
        }
    }

    /**
     * 
     * @return Oauth2Server
     */
    protected function getOauth2Server()
    {
        if(empty($this->_oauth2Server))
            $this->_oauth2Server = \Yii::createObject(Oauth2Server::className());
        return $this->_oauth2Server;
    }
    

    
}
