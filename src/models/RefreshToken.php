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
 * This is the model class for table "{{%oauth2_refresh_token}}".
 *
 * @property string $refresh_token SHA-256 hash of the token, see TokenTrait
 * @property string $client_id
 * @property integer $user_id
 * @property integer $expires
 * @property string $scope
 * @property int|null $used when the token was used, single-use tokens are kept until they expire to detect reuse
 *
 * @property Client $client
 */
class RefreshToken extends ActiveRecord
{
    use TokenTrait;

    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return '{{%oauth2_refresh_token}}';
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            [['refresh_token', 'client_id', 'expires'], 'required'],
            [['user_id', 'expires'], 'integer'],
            [['scope'], 'string'],
            [['used'], 'integer'],
            [['refresh_token'], 'string', 'max' => 64],
            [['client_id'], 'string', 'max' => 80]
        ];
    }

    /**
     * @inheritdoc
     */
    public function attributeLabels()
    {
        return [
            'refresh_token' => 'Refresh Token',
            'client_id' => 'Client ID',
            'user_id' => 'User ID',
            'expires' => 'Expires',
            'scope' => 'Scope',
        ];
    }

    /**
     *
     * @param array $attributes
     * @throws Exception
     * @return \conquer\oauth2\models\RefreshToken
     * @throws \yii\base\Exception
     */
    public static function createRefreshToken(array $attributes)
    {
        $model = static::createWithToken($attributes);
        if ($model === null) {
            throw new Exception(Yii::t('conquer/oauth2', 'Unable to create refresh token.'), Exception::SERVER_ERROR);
        }
        return $model;
    }

    /**
     * @inheritdoc
     */
    public static function tokenAttribute()
    {
        return 'refresh_token';
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
