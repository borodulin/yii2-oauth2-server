<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2\models;

use Yii;

/**
 * This is the model class for table "oauth_client".
 *
 * @property string $client_id
 * @property string $client_secret
 * @property string $redirect_uri
 * @property string $grant_types
 * @property string $scopes
 * @property integer $user_id
 * @property string $public_key
 *
 * @property OauthAccessToken[] $oauthAccessTokens
 * @property OauthAuthorizationCode[] $oauthAuthorizationCodes
 * @property OauthRefreshToken[] $oauthRefreshTokens
 */
class OauthClient extends \yii\db\ActiveRecord
{
    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return '{{%oauth_client}}';
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            [['client_id', 'client_secret', 'redirect_uri', 'user_id', 'public_key'], 'required'],
            [['scopes'], 'string'],
            [['user_id'], 'integer'],
            [['client_id', 'client_secret', 'grant_types'], 'string', 'max' => 80],
            [['redirect_uri', 'public_key'], 'string', 'max' => 2000]
        ];
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
            'grant_types' => 'Space-delimited list of grant types permitted, null = all',
            'scopes' => 'Space-delimited list of approved scopes',
            'user_id' => 'FK to oauth_users.user_id',
            'public_key' => 'Public key for encryption',
        ];
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getOauthAccessTokens()
    {
        return $this->hasMany(OauthAccessToken::className(), ['client_id' => 'client_id']);
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getOauthAuthorizationCodes()
    {
        return $this->hasMany(OauthAuthorizationCode::className(), ['client_id' => 'client_id']);
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getOauthRefreshTokens()
    {
        return $this->hasMany(OauthRefreshToken::className(), ['client_id' => 'client_id']);
    }
    
    public function finishAuthorization()
    {
        
    }
    
}
