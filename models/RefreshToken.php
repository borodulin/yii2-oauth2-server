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
 * This is the model class for table "{{%oauth2_refresh_token}}".
 *
 * @property string $refresh_token
 * @property string $client_id
 * @property integer $user_id
 * @property integer $expires
 * @property string $scope
 *
 * @property Client $client
 *
 * @author Andrey Borodulin
 */
class RefreshToken extends ActiveRecord
{
    /**
     * @throws \yii\base\InvalidConfigException
     */
    public static function tableName()
    {
        return OAuth2::instance()->refreshTokenTable;
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
     * @return \conquer\oauth2\models\RefreshToken
     * @throws \yii\base\Exception
     * @throws \yii\base\InvalidConfigException
     */
    public static function createRefreshToken($clientId, $userId, $scope)
    {
        if (OAuth2::instance()->clearOldTokens) {
            static::deleteAll(['<', 'expires', time()]);
        }
        $refreshToken = new static();
        $refreshToken->refresh_token = Yii::$app->security->generateRandomString(40);
        $refreshToken->client_id = $clientId;
        $refreshToken->user_id = $userId;
        $refreshToken->scope = $scope;
        $refreshToken->save(false);
        return $refreshToken;
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getClient()
    {
        return $this->hasOne(Client::class, ['client_id' => 'client_id']);
    }
}
