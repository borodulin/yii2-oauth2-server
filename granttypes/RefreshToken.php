<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

use conquer\oauth2\models\AccessToken;

/**
 *
 * @author Andrey Borodulin
 */
class RefreshToken extends GrantTypeAbstract
{
    public function rules()
    {
        return [
            [['client_id', 'client_secret', 'refresh_token'], 'required'],
            [['client_id', 'client_secret'], 'string', 'max' => 80],
            [['refresh_token'], 'string', 'max' => 40],
            [['client_id'], 'validateClient_id'],
            [['client_secret'], 'validateClient_secret'],
            [['refresh_token'], 'validateRefresh_token'],
        ];
    }
    
    public function getResponseData()
    {
        $refreshToken = $this->getRefreshToken();
        
        $acessToken = AccessToken::createAccessToken([
            'client_id' => $this->client_id,
            'user_id' => $refreshToken->user_id,
            'expires' => $this->accessTokenLifetime + time(),
            'scope' => $refreshToken->scope,
        ]);
    
        $refreshToken->delete();
        
        $refreshToken = \conquer\oauth2\models\RefreshToken::createRefreshToken([
            'client_id' => $this->client_id,
            'user_id' => $refreshToken->user_id,
            'expires' => $this->refreshTokenLifetime + time(),
            'scope' => $refreshToken->scope,
        ]);
        return  [
            'access_token' => $acessToken->access_token,
            'expires_in' => $this->accessTokenLifetime,
            'token_type' => 'bearer',
            'scope' => $refreshToken->scope,
            'refresh_token' => $refreshToken->refresh_token,
        ];
    }
}
