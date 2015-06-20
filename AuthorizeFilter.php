<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use yii\web\Response;
use conquer\oauth2\Oauth2Server;
use conquer\oauth2\responsetypes\ResponseTypeAbstract;

/**
 * 
 * @author Andrey Borodulin
 * 
 */
class AuthorizeFilter extends \yii\base\ActionFilter
{

    private $_responseType;

    public $authCodeLifetime = 30;
    
    /**
     * @inheritdoc
     */
    public function beforeAction($action)
    {
        $this->_responseType = ResponseTypeAbstract::createResponseType();
        
        $this->_responseType->validate();

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
            $this->_responseType->finishAuthorization();
        }
    }
}
