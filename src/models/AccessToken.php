<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\models;

use conquer\oauth2\Exception;
use Yii;
use yii\db\ActiveRecord;

/**
 * This is the model class for table "oauth_access_token".
 *
 * @property string $access_token SHA-256 hash of the token, see TokenTrait
 * @property string $client_id
 * @property integer $user_id
 * @property integer $expires
 * @property string $scope
 *
 * @property Client $client
 * @property ActiveRecord $user
 */
class AccessToken extends ActiveRecord
{
    use TokenTrait;

    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return '{{%oauth2_access_token}}';
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            [['access_token', 'client_id', 'expires'], 'required'],
            [['user_id', 'expires'], 'integer'],
            [['scope'], 'string'],
            [['access_token'], 'string', 'max' => 64],
            [['client_id'], 'string', 'max' => 80]
        ];
    }

    /**
     * @inheritdoc
     */
    public function attributeLabels()
    {
        return [
            'access_token' => 'Access Token',
            'client_id' => 'Client ID',
            'user_id' => 'User ID',
            'expires' => 'Expires',
            'scope' => 'Scopes',
        ];
    }

    /**
     * @param array $attributes
     * @return static
     * @throws Exception
     * @throws \yii\base\Exception
     */
    public static function createAccessToken(array $attributes)
    {
        $model = static::createWithToken($attributes);
        if ($model === null) {
            throw new Exception(Yii::t('conquer/oauth2', 'Unable to create access token.'), Exception::SERVER_ERROR);
        }
        return $model;
    }

    /**
     * @inheritdoc
     */
    public static function tokenAttribute()
    {
        return 'access_token';
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getClient()
    {
        return $this->hasOne(Client::class, ['client_id' => 'client_id']);
    }

    /**
     * @return \yii\db\ActiveQuery|null null when the identity class is not an ActiveRecord
     */
    public function getUser()
    {
        $identityClass = Yii::$app->user->identityClass;
        if (is_subclass_of($identityClass, ActiveRecord::class)) {
            $primaryKey = $identityClass::primaryKey();
            $key = reset($primaryKey);
            if (is_string($key)) {
                return $this->hasOne($identityClass, [$key => 'user_id']);
            }
        }
        return null;
    }
}
