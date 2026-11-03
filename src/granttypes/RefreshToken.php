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
     * @var \conquer\oauth2\models\RefreshToken
     */
    private $_refreshToken;

    /**
     * Value MUST be set to "refresh_token".
     * @var string
     */
    public $grant_type;

    /**
     * The refresh token issued to the client.
     * @var string
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
            [['client_id', 'grant_type', 'client_secret', 'refresh_token'], 'required'],
            ['grant_type', 'required', 'requiredValue' => 'refresh_token'],
            [['client_id', 'client_secret'], 'string', 'max' => 80],
            [['refresh_token'], 'string', 'max' => 40],
            [['scope'], 'string'],
            [['client_id'], 'validateClientId'],
            [['client_secret'], 'validateClientSecret'],
            [['refresh_token'], 'validateRefreshToken'],
        ];
    }

    public function validateRefreshToken()
    {
        $refreshToken = $this->getRefreshToken();
        $this->checkGrantType('refresh_token');

        if ($refreshToken->client_id !== $this->client_id) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The Refresh Token was issued to another client.'), Exception::INVALID_GRANT);
        }
        if ($refreshToken->expires < time()) {
            $refreshToken->delete();
            $this->errorServer(Yii::t('conquer/oauth2', 'The Refresh Token has expired.'), Exception::INVALID_GRANT);
        }
        if (!empty($this->scope) && !$this->checkSets($this->scope, (string)$refreshToken->scope)) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The requested scope is invalid, unknown, or malformed.'), Exception::INVALID_SCOPE);
        }
    }

    /**
     * @return array
     * @throws Exception
     */
    public function getResponseData()
    {
        $oldToken = $this->getRefreshToken();
        $scope = empty($this->scope) ? $oldToken->scope : $this->scope;

        $acessToken = AccessToken::createAccessToken([
            'client_id' => $this->client_id,
            'user_id' => $oldToken->user_id,
            'expires' => $this->accessTokenLifetime + time(),
            'scope' => $scope,
        ]);

        $oldToken->delete();

        $refreshToken = \conquer\oauth2\models\RefreshToken::createRefreshToken([
            'client_id' => $this->client_id,
            'user_id' => $oldToken->user_id,
            'expires' => $this->refreshTokenLifetime + time(),
            'scope' => $scope,
        ]);

        return [
            'access_token' => $acessToken->access_token,
            'expires_in' => $this->accessTokenLifetime,
            'token_type' => $this->tokenType,
            'scope' => $scope,
            'refresh_token' => $refreshToken->refresh_token,
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
            if (!$this->_refreshToken = \conquer\oauth2\models\RefreshToken::findOne(['refresh_token' => $this->refresh_token])) {
                $this->errorServer(Yii::t('conquer/oauth2', 'The Refresh Token is invalid.'), Exception::INVALID_GRANT);
            }
        }
        return $this->_refreshToken;
    }
}
