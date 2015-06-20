<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\responsetypes;

use conquer\oauth2\OAuth2Trait;

/**
 * @property string $client_id
 * @property string $redirect_uri
 * @property string $scope
 *
 * @author Andrey Borodulin
 */
class AuthorizationCode extends ResponseTypeAbstract
{

    public function rules()
    {
        return [
            [['client_id'], 'required'],
            [['client_id'], 'string', 'max' => 80],
            [['redirect_uri'], 'url'],
            [['client_id'], 'validateClient_id'],
            [['redirect_uri'], 'validateRedirect_uri'],
            [['scope'], 'validateScope'],
            
        ];
    }

    public function getResponseData()
    {
        $authCode = \conquer\oauth2\models\AuthorizationCode::createAuthorizationCode([
            'client_id' => $this->client_id,
            'user_id' => \Yii::$app->user->id,
            'expires' => $this->authCodeLifetime+time(),
            'scope' => $this->scope,
        ]);
        
        return [
            'query'=>[
                "code" => $authCode->authorization_code,
            ],
        ];
    }
    
}


