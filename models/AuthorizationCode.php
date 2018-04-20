<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\models;

use conquer\oauth2\OAuth2;
use Yii;
use yii\db\ActiveRecord;

/**
 * This is the model class for table "oauth_authorization_code".
 *
 * @property string $authorization_code
 * @property string $client_id
 * @property integer $user_id
 * @property string $redirect_uri
 * @property integer $expires
 * @property string $scope
 *
 * @property Client $client
 *
 * @author Andrey Borodulin
 */
class AuthorizationCode extends ActiveRecord
{
    /**
     * @throws \yii\base\InvalidConfigException
     */
    public static function tableName()
    {
        return OAuth2::instance()->authorizationCodeTable;
    }

    /**
     * @return string|\yii\db\Connection
     * @throws \yii\base\InvalidConfigException
     */
    public static function getDb()
    {
        return OAuth2::instance()->db;
    }

    /**
     *
     * @param $clientId
     * @param $userId
     * @param $scope
     * @return AuthorizationCode
     * @throws \yii\base\Exception
     * @throws \yii\base\InvalidConfigException
     */
    public static function create($clientId, $userId, $scope)
    {
        if (OAuth2::instance()->clearOldTokens) {
            static::deleteAll(['<', 'expires', time()]);
        }
        $authCode = new static();
        $authCode->authorization_code = Yii::$app->security->generateRandomString(40);
        $authCode->expires = time() + OAuth2::instance()->authCodeLifetime;
        $authCode->client_id = $clientId;
        $authCode->user_id = $userId;
        $authCode->scope = $scope;
        $authCode->save(false);
        return $authCode;
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getClient()
    {
        return $this->hasOne(Client::class, ['client_id' => 'client_id']);
    }

    /**
     * @return AccessToken
     * @throws \yii\base\Exception
     * @throws \yii\base\InvalidConfigException
     */
    public function createAccessToken()
    {
        return AccessToken::create($this->client_id, $this->user_id, $this->scope);
    }

    /**
     * @return RefreshToken
     * @throws \yii\base\Exception
     * @throws \yii\base\InvalidConfigException
     */
    public function createRefreshToken()
    {
        return RefreshToken::create($this->client_id, $this->user_id, $this->scope);
    }
}
