<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\models;

use Yii;
use yii\behaviors\BlameableBehavior;
use yii\behaviors\TimestampBehavior;

/**
 * This is the model class for table "oauth2_client".
 *
 * @property string $client_id
 * @property string $client_secret bcrypt hash of the secret, empty for public clients
 * @property string $redirect_uri
 * @property string $grant_type
 * @property string $scope
 * @property integer $user_id
 * @property string|null $public_key PEM encoded public key for JWT assertions (RFC 7523)
 *
 * @property AccessToken[] $accessTokens
 * @property AuthorizationCode[] $authorizationCodes
 * @property RefreshToken[] $refreshTokens
 */
class Client extends \yii\db\ActiveRecord
{
    /**
     * @var int bcrypt cost of client secret hashes; every token request with a secret checks the hash
     */
    public $secretHashCost = 10;

    /**
     * @return void
     */
    public function init()
    {
        \conquer\oauth2\Translations::register();
        parent::init();
    }

    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return '{{%oauth2_client}}';
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        $rules = [
            [['client_id', 'redirect_uri'], 'required'],
            // empty secret and no public key: a public client (SPA, mobile app), it must use PKCE
            [['client_secret'], 'default', 'value' => ''],
            [['scope'], 'string'],
            [['client_id', 'client_secret', 'grant_type'], 'string', 'max' => 80],
            [['redirect_uri'], 'string', 'max' => 2000],
        ];
        // the column is added by m261122_120000_oauth_jwt
        if ($this->hasAttribute('public_key')) {
            $rules[] = [['public_key'], 'string'];
        }
        return $rules;
    }

    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        return [
            TimestampBehavior::class,
            BlameableBehavior::class,
        ];
    }

    /**
     * @inheritdoc
     */
    public function attributeLabels()
    {
        return [
            'client_id' => Yii::t('conquer/oauth2', 'Unique client identifier'),
            'client_secret' => Yii::t('conquer/oauth2', 'Client secret'),
            'redirect_uri' => Yii::t('conquer/oauth2', 'Redirect URI used for Authorization Grant'),
            'grant_type' => Yii::t('conquer/oauth2', 'Space-delimited list of grant types permitted, null = all'),
            'scope' => Yii::t('conquer/oauth2', 'Space-delimited list of approved scopes'),
            'public_key' => Yii::t('conquer/oauth2', 'PEM encoded public key for JWT assertions'),
        ];
    }

    /**
     * Whether the client is public (RFC 6749, 2.1): it has neither a secret nor a public key,
     * so it cannot authenticate. Public clients must use PKCE and cannot use client_credentials or password.
     * @return bool
     */
    public function isPublic()
    {
        return (string)$this->client_secret === '' && $this->getPublicKey() === null;
    }

    /**
     * Checks a client secret against the stored bcrypt hash.
     * @param string $secret
     * @return bool
     */
    public function validateSecret($secret)
    {
        $stored = (string)$this->client_secret;
        if ($secret === '' || !self::isSecretHash($stored)) {
            return false;
        }
        return Yii::$app->security->validatePassword($secret, $stored);
    }

    /**
     * Generates a new random secret and stores its hash; save() the model afterwards.
     * @return string the secret to give to the client, it cannot be recovered later
     * @throws \yii\base\Exception
     */
    public function generateSecret()
    {
        $secret = Yii::$app->security->generateRandomString(40);
        $this->client_secret = $secret;
        return $secret;
    }

    /**
     * @param string $value
     * @return bool whether the value is a bcrypt hash
     */
    public static function isSecretHash($value)
    {
        return (bool)preg_match('/^\$2[axy]\$\d\d\$[.\/A-Za-z0-9]{53}$/', $value);
    }

    /**
     * Client secrets are stored as bcrypt hashes; a plain secret assigned to client_secret is hashed on save.
     * @inheritdoc
     */
    public function beforeSave($insert)
    {
        $secret = (string)$this->client_secret;
        if ($secret !== '' && !self::isSecretHash($secret)) {
            $this->client_secret = Yii::$app->security->generatePasswordHash($secret, $this->secretHashCost);
        }
        return parent::beforeSave($insert);
    }

    /**
     * Returns the public key that verifies JWTs signed by the client (RFC 7523).
     * @return string|null null when no key is registered or the table has no public_key column
     */
    public function getPublicKey()
    {
        if (!$this->hasAttribute('public_key') || !is_string($this->public_key) || trim($this->public_key) === '') {
            return null;
        }
        return $this->public_key;
    }

    /**
     * @return string[] registered redirect URIs (whitespace-separated in the redirect_uri column)
     */
    public function getRedirectUris()
    {
        return preg_split('/\s+/', trim((string)$this->redirect_uri), -1, PREG_SPLIT_NO_EMPTY) ?: [];
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
