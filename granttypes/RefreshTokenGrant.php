<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

use conquer\oauth2\BaseModel;
use conquer\oauth2\models\RefreshToken;
use conquer\oauth2\OAuth2;

/**
 * Class RefreshToken
 * @package conquer\oauth2\granttypes
 * @author Andrey Borodulin
 */
class RefreshTokenGrant extends BaseModel
{
    /**
     * @var RefreshToken
     */
    private $_refreshToken;

    /**
     * The refresh token issued to the client.
     * @var string
     */
    public $refresh_token;
    /**
     * The scope of the access request as described by Section 3.3.
     * @var string
     */
    public $scope;
    /**
     *
     * @var string
     */
    public $client_id;
    /**
     *
     * @var string
     */
    public $client_secret;

    public function rules()
    {
        return [
            [['client_id', 'client_secret', 'refresh_token'], 'required'],
            [['client_id', 'client_secret'], 'string', 'max' => 80],
            [['refresh_token'], 'string', 'max' => 40],
            [['client_id'], 'validateClientId'],
            [['client_secret'], 'validateClientSecret'],
            [['refresh_token'], 'validateRefreshToken'],
        ];
    }

    /**
     * @return array
     * @throws \Exception
     * @throws \Throwable
     * @throws \conquer\oauth2\Exception
     * @throws \yii\base\Exception
     * @throws \yii\db\StaleObjectException
     */
    public function getResponseData()
    {
        $oldRefreshToken = $this->getRefreshToken();

        $accessToken = $oldRefreshToken->createAccessToken();
        $newRefreshToken = $oldRefreshToken->createRefreshToken();

        $oldRefreshToken->delete();

        $oauth2 = OAuth2::instance();

        return [
            'access_token' => $accessToken->access_token,
            'expires_in' => $oauth2->refreshTokenLifetime,
            'token_type' => $oauth2->tokenType,
            'scope' => $newRefreshToken->scope,
            'refresh_token' => $newRefreshToken->refresh_token,
        ];
    }

    /**
     * @throws \conquer\oauth2\Exception
     */
    public function validateRefreshToken()
    {
        $this->getRefreshToken();
    }

    /**
     * @return RefreshToken
     * @throws \conquer\oauth2\Exception
     */
    public function getRefreshToken()
    {
        if ($this->_refreshToken === null) {
            if (!$this->_refreshToken = RefreshToken::findOne(['refresh_token' => $this->refresh_token])) {
                $this->errorServer('The Refresh Token is invalid');
            }
        }
        return $this->_refreshToken;
    }
}
