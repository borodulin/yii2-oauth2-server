<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\models;

use conquer\oauth2\OAuth2;
use yii\behaviors\BlameableBehavior;
use yii\behaviors\TimestampBehavior;
use yii\db\ActiveRecord;

/**
 * This is the model class for table "oauth2_client".
 *
 * @property string $client_id
 * @property string $client_secret
 * @property string $redirect_uri
 * @property string $grant_type
 * @property string $scope
 * @property integer $user_id
 * @property string $public_key
 *
 * @property AccessToken[] $accessTokens
 * @property AuthorizationCode[] $authorizationCodes
 * @property RefreshToken[] $refreshTokens
 *
 * @author Andrey Borodulin
 */
class Client extends ActiveRecord
{
    /**
     * @throws \yii\base\InvalidConfigException
     */
    public static function tableName()
    {
        return OAuth2::instance()->clientTable;
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
     * @inheritdoc
     */
    public function attributeLabels()
    {
        return [
            'client_id' => 'Unique client identifier',
            'client_secret' => 'Client secret',
            'redirect_uri' => 'Redirect URI used for Authorization Grant',
            'grant_type' => 'Space-delimited list of grant types permitted, null = all',
            'scope' => 'Space-delimited list of approved scopes',
        ];
    }

    /**
     * @return array
     */
    public function behaviors()
    {
        return [
            TimestampBehavior::class,
            BlameableBehavior::class,
        ];
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getAccessTokens()
    {
        return $this->hasMany(AccessToken::class, ['client_id' => 'client_id']);
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getAuthorizationCodes()
    {
        return $this->hasMany(AuthorizationCode::class, ['client_id' => 'client_id']);
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getRefreshTokens()
    {
        return $this->hasMany(RefreshToken::class, ['client_id' => 'client_id']);
    }
}
