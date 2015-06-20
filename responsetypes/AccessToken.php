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
class AccessToken extends ResponseTypeAbstract
{
    public $tokeType = 'bearer';
    
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
        $accessToken = \conquer\oauth2\models\AccessToken::createAccessToken([
                'client_id' => $this->client_id,
                'user_id' => \Yii::$app->user->id,
                'expires' => $this->accessTokenLifetime + time(),
                'scope' => $this->scope,
        ]);
        $refreshToken = \conquer\oauth2\models\RefreshToken::createRefreshToken([
                'client_id' => $this->client_id,
                'user_id' => \Yii::$app->user->id,
                'expires' => $this->refreshTokenLifetime + time(),
                'scope' => $this->scope,
        ]);
        return [
            'fragment'=>[
                "access_token" => $accessToken->access_token,
                "expires_in" => $this->accessTokenLifetime,
                "token_type" => $this->tokeType,
                "scope" => $this->scope,
                'refresh_token' => $refreshToken->refresh_token,
            ],
        ];
    }
    
}

