<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

use conquer\oauth2\BaseModel;
use conquer\oauth2\models\AccessToken;
use conquer\oauth2\models\RefreshToken;
use conquer\oauth2\OAuth2IdentityInterface;
use Yii;
use yii\web\IdentityInterface;

/**
 * For example, the client makes the following HTTP request using
 * transport-layer security (with extra line breaks for display purposes
 * only):
 *
 * ```
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 * Content-Type: application/x-www-form-urlencoded
 *
 * grant_type=password&username=johndoe&password=A3ddj3w
 * ```
 *
 * @link https://tools.ietf.org/html/rfc6749#section-4.3
 * @author Dmitry Fedorenko
 */
class UserCredentials extends BaseModel
{
    /**
     * bcrypt hash (cost 13, the Yii default) checked when the user does not exist
     */
    const DUMMY_PASSWORD_HASH = '$2y$13$wfr3uy.Wc06ySoxIonqUHuW4ZxJxOJ7mUTKqx3sBmtCZUgqEEBS9e';

    private $_user;

    /**
     * Value MUST be set to "password"
     * @var string
     */
    public $grant_type;

    /**
     * The resource owner username.
     * @var string
     */
    public $username;

    /**
     * The resource owner password.
     * @var string
     */
    public $password;

    /**
     * Access Token Scope
     * @link https://tools.ietf.org/html/rfc6749#section-3.3
     * @var string
     */
    public $scope;

    /**
     * @var string
     */
    public $client_id;

    /**
     * @var string
     */
    public $client_secret;

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            [['grant_type', 'client_id', 'username', 'password'], 'required'],
            ['grant_type', 'required', 'requiredValue' => 'password'],
            [['client_id', 'client_secret'], 'string', 'max' => 80],
            [['username', 'password', 'scope'], 'string'],
            [['client_id'], 'validateClientId'],
            [['client_secret'], 'validateClientSecret', 'skipOnEmpty' => false],
            [['grant_type'], 'validateGrantType'],
            [['scope'], 'validateScope'],
            // password is validated by validatePassword()
            ['password', 'validatePassword'],
        ];
    }

    /**
     * Validates the password.
     * This method serves as the inline validation for password.
     * @param string $attribute the attribute currently being validated
     * @throws \conquer\oauth2\Exception
     * @throws \yii\base\InvalidConfigException
     */
    public function validatePassword($attribute)
    {
        /** @var OAuth2IdentityInterface|null $user */
        $user = $this->getUser();
        if (!$user) {
            // spend the time of a password check, so that response times do not reveal existing usernames
            Yii::$app->security->validatePassword((string)$this->password, self::DUMMY_PASSWORD_HASH);
        }
        if (!$user || !$user->validatePassword($this->password)) {
            $this->addError($attribute, Yii::t('conquer/oauth2', 'Invalid username or password.'));
        }
    }

    /**
     * @inheritdoc
     */
    public function getResponseData()
    {
        /** @var IdentityInterface $identity */
        $identity = $this->getUser();

        $accessToken = AccessToken::createAccessToken([
            'client_id' => $this->client_id,
            'user_id' => $identity->getId(),
            'expires' => $this->accessTokenLifetime + time(),
            'scope' => $this->scope,
        ]);

        $refreshToken = RefreshToken::createRefreshToken([
            'client_id' => $this->client_id,
            'user_id' => $identity->getId(),
            'expires' => $this->refreshTokenLifetime + time(),
            'scope' => $this->scope,
        ]);

        return [
            'access_token' => $accessToken->token,
            'expires_in' => $this->accessTokenLifetime,
            'token_type' => $this->tokenType,
            'scope' => $this->scope,
            'refresh_token' => $refreshToken->token,
        ];
    }

    /**
     * Finds user by [[username]]
     * @return IdentityInterface|null
     * @throws \yii\base\InvalidConfigException
     * @throws \conquer\oauth2\Exception
     */
    protected function getUser()
    {
        /** @var OAuth2IdentityInterface $identityClass */
        $identityClass = Yii::$app->user->identityClass;

        $identityObject = Yii::createObject($identityClass);
        if (! $identityObject instanceof OAuth2IdentityInterface) {
            $this->errorServer(Yii::t('conquer/oauth2', 'OAuth2IdentityInterface is not implemented.'));
        }

        if ($this->_user === null) {
            $this->_user = $identityClass::findIdentityByUsername($this->username);
        }

        return $this->_user;
    }

    public function validateGrantType()
    {
        $this->requireConfidentialClient();
        $this->checkGrantType('password');
    }
}
