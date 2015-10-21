<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use yii\web\Response;
use conquer\oauth2\granttypes\GrantTypeAbstract;

/**
 * 
 * @author Andrey Borodulin
 *
 */
class TokenAction extends \yii\base\Action
{
    
    /**
     * Access Token lifetime
     * 1 hour by default
     * @var integer
     */
    public $accessTokenLifetime = 3600;
    /**
     * Refresh Token lifetime
     * 2 weeks by default
     * @var integer
     */
    public $refreshTokenLifetime = 1209600;
    
    public function init()
    {
        \Yii::$app->response->format = Response::FORMAT_JSON;
        $this->controller->enableCsrfValidation = false;
    }
    
    public function run()
    {
        $request = \Yii::$app->request;
        
        $grantType = GrantTypeAbstract::createGrantType([
                'accessTokenLifetime' => $this->accessTokenLifetime,
                'refreshTokenLifetime' => $this->refreshTokenLifetime,
        ]);
        
        $grantType->validate();
        
        \Yii::$app->response->data = $grantType->getResponseData();
    }
}