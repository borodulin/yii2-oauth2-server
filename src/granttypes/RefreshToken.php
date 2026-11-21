<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

use conquer\oauth2\BaseModel;
use conquer\oauth2\Exception;
use conquer\oauth2\models\AccessToken;
use Yii;

/**
 * Refresh token grant.
 * @link https://tools.ietf.org/html/rfc6749#section-6
 * @author Andrey Borodulin
 */
class RefreshToken extends BaseModel
{
    /**
     * @var \conquer\oauth2\models\RefreshToken|null
     */
    private $_refreshToken;

    /**
     * Value MUST be set to "refresh_token".
     * @var string
     */
    public $grant_type;

    /**
     * The refresh token issued to the client.
     * @var mixed raw request value, checked in getRefreshToken()
     */
    public $refresh_token;

    /**
     * The requested scope MUST NOT include any scope not originally granted by the resource owner.
     * If omitted is treated as equal to the scope originally granted.
     * @var string
     */
    public $scope;

    /**
     * @var string
     */
    public $client_id;

    /**
     * @var string
     */
    public $client_secret;

    public function rules()
    {
        return [
            [['client_id', 'grant_type', 'refresh_token'], 'required'],
            ['grant_type', 'required', 'requiredValue' => 'refresh_token'],
            [['client_id', 'client_secret'], 'string', 'max' => 80],
            [['refresh_token'], 'string', 'max' => 40],
            [['scope'], 'string'],
            [['client_id'], 'validateClientId'],
            [['client_secret'], 'validateClientSecret', 'skipOnEmpty' => false],
            [['refresh_token'], 'validateRefreshToken'],
        ];
    }

    /**
     * @return void
     * @throws Exception
     */
    public function validateRefreshToken()
    {
        $refreshToken = $this->getRefreshToken();
        if ($refreshToken->used !== null) {
            // a rotated refresh token was used again: it has leaked (RFC 9700, 4.14.2)
            $this->revokeTokens($refreshToken->client_id, $refreshToken->user_id);
            $this->errorServer(Yii::t('conquer/oauth2', 'The Refresh Token is invalid.'), Exception::INVALID_GRANT);
        }
        $this->checkGrantType('refresh_token');
        if ($refreshToken->client_id !== $this->client_id) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The Refresh Token was issued to another client.'), Exception::INVALID_GRANT);
        }
        if ($refreshToken->expires < time()) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The Refresh Token has expired.'), Exception::INVALID_GRANT);
        }
        if (!empty($this->scope)
            && !$this->checkSets($this->scope, implode(' ', $this->getGrantedScope()))
        ) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The requested scope is invalid, unknown, or malformed.'), Exception::INVALID_SCOPE);
        }
    }

    /**
     * The originally granted scope, without scopes the client is no longer allowed.
     * @return string[]
     */
    protected function getGrantedScope()
    {
        $clientScope = self::splitScope($this->getClient()->scope);
        return array_values(array_intersect(self::splitScope($this->getRefreshToken()->scope), $clientScope));
    }

    /**
     * @return array<string, mixed>
     * @throws Exception
     */
    public function getResponseData()
    {
        $oldToken = $this->getRefreshToken();
        $granted = implode(' ', $this->getGrantedScope());
        // the access token may get a narrower scope, the new refresh token keeps the granted scope (RFC 6749, 6)
        $scope = empty($this->scope) ? $granted : implode(' ', self::splitScope($this->scope));
        // rotate atomically: concurrent requests with the same refresh token must not both succeed
        if (!$oldToken->markUsed()) {
            $this->revokeTokens($oldToken->client_id, $oldToken->user_id);
            $this->errorServer(Yii::t('conquer/oauth2', 'The Refresh Token is invalid.'), Exception::INVALID_GRANT);
        }

        $acessToken = AccessToken::createAccessToken([
            'client_id' => $this->client_id,
            'user_id' => $oldToken->user_id,
            'expires' => $this->accessTokenLifetime + time(),
            'scope' => $scope,
        ]);

        $refreshToken = \conquer\oauth2\models\RefreshToken::createRefreshToken([
            'client_id' => $this->client_id,
            'user_id' => $oldToken->user_id,
            'expires' => $this->refreshTokenLifetime + time(),
            'scope' => $granted,
        ]);

        return [
            'access_token' => $acessToken->token,
            'expires_in' => $this->accessTokenLifetime,
            'token_type' => $this->tokenType,
            'scope' => $scope,
            'refresh_token' => $refreshToken->token,
        ];
    }

    /**
     * @return \conquer\oauth2\models\RefreshToken
     * @throws Exception
     */
    public function getRefreshToken()
    {
        if (is_null($this->_refreshToken)) {
            if (empty($this->refresh_token) || !is_string($this->refresh_token)) {
                $this->errorServer(Yii::t('conquer/oauth2', 'The request is missing "refresh_token" parameter.'));
            }
            if (!$this->_refreshToken = \conquer\oauth2\models\RefreshToken::findByToken($this->refresh_token)) {
                $this->errorServer(Yii::t('conquer/oauth2', 'The Refresh Token is invalid.'), Exception::INVALID_GRANT);
            }
        }
        return $this->_refreshToken;
    }
}
