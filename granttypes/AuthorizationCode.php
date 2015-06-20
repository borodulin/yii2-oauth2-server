<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

use conquer\oauth2\models\Client;
use conquer\oauth2\models\AccessToken;
use conquer\oauth2\models\RefreshToken;

/**
 * @param string $client_id
 * @param string $client_secret
 * @param string $code
 * @param string $redirect_uri
 * @param string $state
 * 
 * @author Andrey Borodulin
 */
class AuthorizationCode extends GrantTypeAbstract
{
    
    public function rules()
    {
        return [
            [['client_id', 'client_secret', 'code'], 'required'],
            [['client_id', 'client_secret'], 'string', 'max' => 80],
            [['code'], 'string', 'max' => 40],
            [['redirect_uri'], 'url'],
            [['code'], 'validateCode'],
            [['client_id'], 'validateClient_id'],
            [['client_secret'], 'validateClient_secret'],
        ];
    }
    
    public function getResponseData()
    {
        $authCode = $this->getAuthCode();
        $acessToken = AccessToken::createAccessToken([
            'client_id' => $this->client_id,
            'user_id' => $authCode->user_id,
            'expires' => $this->accessTokenLifetime + time(),
            'scope' => $authCode->scope,
        ]);
        
        $refreshToken = RefreshToken::createRefreshToken([
            'client_id' => $this->client_id,
            'user_id' => $authCode->user_id,
            'expires' => $this->refreshTokenLifetime + time(),
            'scope' => $authCode->scope,
        ]);
        return  [
            'access_token' => $acessToken->access_token,
            'expires_in' => $this->accessTokenLifetime,
            'token_type' => 'bearer',
            'scope' => $this->scope,
            'refresh_token' => $refreshToken->refresh_token,
        ];
    }
}
