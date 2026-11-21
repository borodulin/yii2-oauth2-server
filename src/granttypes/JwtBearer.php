<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

use conquer\oauth2\BaseModel;
use conquer\oauth2\Exception;
use conquer\oauth2\JwtValidator;
use conquer\oauth2\models\AccessToken;
use Yii;
use yii\web\IdentityInterface;

/**
 * JWT bearer grant (RFC 7523, section 2.1).
 *
 * The client signs a JWT with its private key and exchanges it for an access token of the user
 * identified by the "sub" claim. The "iss" claim is the client ID, the JWT is verified with
 * Client::$public_key. See JwtValidator for the other checks.
 *
 * This grant lets the client get tokens of any user, so a client must be explicitly allowed to use it:
 * Client::$grant_type has to contain "urn:ietf:params:oauth:grant-type:jwt-bearer".
 *
 * Client authentication (client_secret or client_assertion) is optional; when present, it is verified.
 *
 * @link https://tools.ietf.org/html/rfc7523
 *
 * @author Andrey Borodulin
 */
class JwtBearer extends BaseModel
{
    const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    /**
     * @var string
     */
    public $grant_type;

    /**
     * The JWT.
     * @var mixed raw request value
     */
    public $assertion;

    /**
     * Access Token Scope
     * @link https://tools.ietf.org/html/rfc6749#section-3.3
     * @var string|null
     */
    public $scope;

    /**
     * Optional, must be equal to the "iss" claim when present.
     * @var mixed raw request value
     */
    public $client_id;

    /**
     * @var mixed raw request value
     */
    public $client_secret;

    /**
     * @var int|string|null ID of the user the token is issued to
     */
    private $_userId;

    public function rules()
    {
        return [
            [['grant_type', 'assertion'], 'required'],
            ['grant_type', 'required', 'requiredValue' => self::GRANT_TYPE],
            [['client_id', 'client_secret'], 'string', 'max' => 80],
            [['assertion', 'scope'], 'string'],
            [['assertion'], 'validateAssertion'],
            [['client_secret'], 'validateClientSecret', 'skipOnEmpty' => false, 'when' => function () {
                return $this->hasClientCredentials();
            }],
            [['scope'], 'validateScope'],
        ];
    }

    /**
     * Verifies the assertion and finds the user it was issued for.
     * @return void
     * @throws Exception
     * @throws \yii\base\InvalidConfigException
     */
    public function validateAssertion()
    {
        $claims = JwtValidator::peekClaims($this->assertion);
        $issuer = isset($claims['iss']) && is_string($claims['iss']) ? $claims['iss'] : null;
        if ($issuer === null) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The assertion is invalid.'), Exception::INVALID_GRANT);
        }
        if (!empty($this->client_id) && $this->client_id !== $issuer) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The assertion was issued by another client.'), Exception::INVALID_GRANT);
        }
        $this->client_id = $issuer;
        $client = $this->getClient();

        if (!in_array(self::GRANT_TYPE, self::splitScope($client->grant_type), true)) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The grant type is unauthorized for this client.'), Exception::UNAUTHORIZED_CLIENT);
        }
        $publicKey = $client->getPublicKey();
        if ($publicKey === null) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The client has no public key.'), Exception::UNAUTHORIZED_CLIENT);
        }

        try {
            $claims = $this->getJwtValidator()->validate((string)$this->assertion, $publicKey, $issuer);
        } catch (\UnexpectedValueException $e) {
            Yii::info('Invalid assertion of ' . $issuer . ': ' . $e->getMessage(), __METHOD__);
            $this->errorServer(Yii::t('conquer/oauth2', 'The assertion is invalid.'), Exception::INVALID_GRANT);
        }

        /** @var class-string<IdentityInterface> $identityClass */
        $identityClass = Yii::$app->user->identityClass;
        $identity = $identityClass::findIdentity($claims['sub']);
        if ($identity === null) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The assertion subject is unknown.'), Exception::INVALID_GRANT);
        }
        $this->_userId = $identity->getId();
    }

    /**
     * @inheritdoc
     */
    public function getResponseData()
    {
        $accessToken = AccessToken::createAccessToken([
            'client_id' => $this->client_id,
            'user_id' => $this->_userId,
            'expires' => $this->accessTokenLifetime + time(),
            'scope' => $this->scope,
        ]);

        return [
            'access_token' => $accessToken->access_token,
            'expires_in' => $this->accessTokenLifetime,
            'token_type' => $this->tokenType,
            'scope' => $this->scope,
        ];
    }
}
