<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\models;

use conquer\oauth2\Exception;
use yii\helpers\VarDumper;
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
 * @property User $user
 */
class AccessToken extends \yii\db\ActiveRecord
{
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
            [['access_token', 'client_id', 'user_id', 'expires'], 'required'],
            [['user_id', 'expires'], 'integer'],
            [['scope'], 'string'],
            [['access_token'], 'string', 'max' => 40],
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
     * @throws Exception
     * @return \conquer\oauth2\models\AccessToken
     */
    public static function createAccessToken(array $attributes)
    {
        static::deleteAll(['<', 'expires', time()]);
        
        $attributes['access_token'] = \Yii::$app->security->generateRandomString(40);
        $accessToken = new static($attributes);

        if ($accessToken->save()) {
            return $accessToken;
        } else {
            \Yii::error(__CLASS__. ' validation error:'. VarDumper::dumpAsString($accessToken->errors));
        }
        throw new Exception('Unable to create access token', Exception::SERVER_ERROR);
    }
    
    /**
     * @return \yii\db\ActiveQuery
     */
    public function getClient()
    {
        return $this->hasOne(Client::className(), ['client_id' => 'client_id']);
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getUser()
    {
        $identity = isset(\Yii::$app->user->identity) ? \Yii::$app->user->identity : null;
        if ($identity instanceof ActiveRecord) {
            return $this->hasOne(get_class($identity), ['user_id' => $identity->primaryKey()]);
        }
    }
}
