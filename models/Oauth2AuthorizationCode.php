<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\models;

use Yii;

/**
 * This is the model class for table "oauth_authorization_code".
 *
 * @property string $authorization_code
 * @property string $client_id
 * @property integer $user_id
 * @property string $redirect_uri
 * @property integer $expires
 * @property string $scopes
 * @property string $id_token
 *
 * @property OauthClient $client
 * @property User $user
 */
class Oauth2AuthorizationCode extends \yii\db\ActiveRecord
{
    /**
     * 
     * @var OauthClient
     */
    private $_client;
    
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
            [['authorization_code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'id_token'], 'required'],
            [['user_id', 'expires'], 'integer'],
            [['scopes'], 'string'],
            [['authorization_code'], 'string', 'max' => 40],
            [['client_id', 'id_token'], 'string', 'max' => 80],
            [['redirect_uri'], 'string', 'max' => 2000]
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
            'scopes' => 'Scopes',
            'id_token' => 'Id Token',
        ];
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getClient()
    {
        return $this->hasOne(OauthClient::className(), ['client_id' => 'client_id']);
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getUser()
    {
        return $this->hasOne(User::className(), ['user_id' => 'user_id']);
    }
}