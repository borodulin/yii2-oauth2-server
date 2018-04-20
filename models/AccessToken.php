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
 * This is the model class for table "oauth_access_token".
 *
 * @property string $access_token
 * @property string $client_id
 * @property integer $user_id
 * @property integer $expires
 * @property string $scope
 *
 * @property Client $client
 *
 * @author Andrey Borodulin
 */
class AccessToken extends ActiveRecord
{
    /**
     * @throws \yii\base\InvalidConfigException
     */
    public static function tableName()
    {
        return OAuth2::instance()->accessTokenTable;
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
     * @param $clientId
     * @param $userId
     * @param $scope
     * @return AccessToken
     * @throws \yii\base\Exception
     * @throws \yii\base\InvalidConfigException
     */
    public static function create($clientId, $userId, $scope)
    {
        if (OAuth2::instance()->clearOldTokens) {
            static::deleteAll(['<', 'expires', time()]);
        }
        $accessToken = new static();
        $accessToken->access_token = Yii::$app->security->generateRandomString(40);
        $accessToken->expires = time() + OAuth2::instance()->accessTokenLifetime;
        $accessToken->client_id = $clientId;
        $accessToken->user_id = $userId;
        $accessToken->scope = $scope;
        $accessToken->save(false);
        return $accessToken;
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getClient()
    {
        return $this->hasOne(Client::class, ['client_id' => 'client_id']);
    }
}
