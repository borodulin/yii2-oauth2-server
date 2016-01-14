<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\models;

use Yii;
use conquer\oauth2\Exception;
use yii\helpers\VarDumper;

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
 * @property User $user
 */
class AuthorizationCode extends \yii\db\ActiveRecord
{
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
            [['authorization_code'], 'string', 'max' => 40],
            [['client_id'], 'string', 'max' => 80],
            [['redirect_uri'], 'url'],
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
     * @return \conquer\oauth2\models\AuthorizationCode
     */
    public static function createAuthorizationCode(array $params)
    {
        static::deleteAll(['<', 'expires', time()]);
        
        $params['authorization_code'] = \Yii::$app->security->generateRandomString(40); 
        $authCode = new static($params);

        if ($authCode->save()) {
            return $authCode;
        } else {
            \Yii::error(__CLASS__.' validation error: '.VarDumper::dumpAsString($authCode->errors));
        }
        throw new Exception('Unable to create authorization code', Exception::SERVER_ERROR);
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
        return $this->hasOne(User::className(), ['user_id' => 'user_id']);
    }
}