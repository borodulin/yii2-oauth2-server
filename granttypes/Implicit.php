<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

use conquer\oauth2\models\AccessToken;

/**
 * @link https://tools.ietf.org/html/rfc6749#section-4.2
 * 
 * @author Andrey Borodulin
 */
class Implicit extends GrantTypeAbstract
{
    public function rules()
    {
        return [
            [['client_id'], 'required'],
            [['client_id'], 'string', 'max' => 80],
            [['redirect_uri'], 'url'],
            [['client_id'], 'validateClient_id'],
            [['scope'], 'validateScope'],
        ];
    }
    
    /**
     * 
     * @link https://tools.ietf.org/html/rfc6749#section-4.2.2
     * @return array
     */
    public function getResponseData()
    {
        $acessToken = AccessToken::createAccessToken([
            'client_id' => $this->client_id,
            'user_id' => \Yii::$app->user->id,
            'expires' => $this->accessTokenLifetime + time(),
            'scope' => $this->scope,
        ]);
        
        // The authorization server MUST NOT issue a refresh token.
        
        return  [
            'access_token' => $acessToken->access_token,
            'expires_in' => $this->accessTokenLifetime,
            'token_type' => $this->tokenType,
            'scope' => $this->scope,
        ];
    }
}