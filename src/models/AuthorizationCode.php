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
 * This is the model class for table "oauth_authorization_code".
 *
 * @property string $authorization_code SHA-256 hash of the token, see TokenTrait
 * @property string $client_id
 * @property integer $user_id
 * @property string $redirect_uri
 * @property integer $expires
 * @property string $scope
 * @property int|null $used when the token was used, single-use tokens are kept until they expire to detect reuse
 * @property string|null $code_challenge
 * @property string|null $code_challenge_method
 *
 * @property Client $client
 * @property ActiveRecord $user
 */
class AuthorizationCode extends ActiveRecord
{
    use TokenTrait;

    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return '{{%oauth2_authorization_code}}';
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            [['authorization_code', 'client_id', 'user_id', 'expires'], 'required'],
            [['user_id', 'expires'], 'integer'],
            [['scope'], 'string'],
            [['used'], 'integer'],
            [['authorization_code'], 'string', 'max' => 64],
            [['client_id'], 'string', 'max' => 80],
            [['redirect_uri'], 'string'],
            [['code_challenge'], 'string', 'max' => 128],
            [['code_challenge_method'], 'string', 'max' => 10],
        ];
    }

    /**
     * @inheritdoc
     */
    public function attributeLabels()
    {
        return [
            'authorization_code' => 'Authorization Code',
            'client_id' => 'Client ID',
            'user_id' => 'User ID',
            'redirect_uri' => 'Redirect Uri',
            'expires' => 'Expires',
            'scope' => 'Scopes',
        ];
    }

    /**
     *
     * @param array $params
     * @throws Exception
     * @return AuthorizationCode
     * @throws \yii\base\Exception
     */
    public static function createAuthorizationCode(array $params)
    {
        $model = static::createWithToken($params);
        if ($model === null) {
            throw new Exception(Yii::t('conquer/oauth2', 'Unable to create authorization code.'), Exception::SERVER_ERROR);
        }
        return $model;
    }

    /**
     * @inheritdoc
     */
    public static function tokenAttribute()
    {
        return 'authorization_code';
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
