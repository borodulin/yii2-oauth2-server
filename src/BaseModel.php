<?php

namespace conquer\oauth2;

use conquer\oauth2\models\Client;
use Yii;
use yii\base\Model;
use yii\web\Request;

/**
 * @property Client $client
 * @property mixed $client_id
 * @property mixed $client_secret
 * @property mixed $redirect_uri declared by the authorization request models
 * @property mixed $scope
 */
abstract class BaseModel extends Model
{
    /**
     * Client assertion type for client authentication with a JWT (RFC 7523, section 2.2).
     */
    const CLIENT_ASSERTION_TYPE_JWT = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    /**
     * @var string|null issuer identifier of the authorization server, sent as "iss" in authorization
     * responses (RFC 9207) when set
     */
    public $issuer;

    /**
     * @var JwtValidator|array<string, mixed>|string validator of JWT assertions
     */
    public $jwtValidator = JwtValidator::class;

    /**
     * @var mixed client_assertion_type request parameter
     */
    protected $_clientAssertionType;

    /**
     * @var mixed client_assertion request parameter
     */
    protected $_clientAssertion;

    /**
     * @var bool whether the request used HTTP Basic and body credentials at the same time
     */
    protected $_multipleClientAuth = false;

    /**
     * @var Client|null
     */
    protected $_client;

    /**
     * @link https://tools.ietf.org/html/rfc6749#section-7.1
     * @var string
     */
    public $tokenType = 'bearer';

    /**
     * Authorization Code lifetime
     * 30 seconds by default
     * @var integer
     */
    public $authCodeLifetime = 30;

    /**
     * Access Token lifetime
     * 1 hour by default
     * @var integer
     */
    public $accessTokenLifetime = 3600;

    /**
     * Refresh Token lifetime
     * 2 weeks by default
     * @var integer
     */
    public $refreshTokenLifetime = 1209600;

    /**
     * @inheritdoc
     */
    public function init()
    {
        Translations::register();
        parent::init();
        $attributes = $this->safeAttributes();
        foreach ($attributes as $attribute) {
            // parameters missing in the request keep their configured defaults
            $value = self::getRequestValue($attribute);
            if ($value !== null) {
                $this->$attribute = $value;
            }
        }
        // HTTP Basic client authentication (RFC 6749, 2.3.1), only for requests that authenticate the client
        if (in_array('client_secret', $attributes, true)) {
            $request = Yii::$app->request;
            if ($request instanceof Request) {
                list($user, $password) = $request->getAuthCredentials();
                if ($user !== null && $user !== '') {
                    $user = urldecode($user);
                    // RFC 6749, 2.3: the client MUST NOT use more than one authentication method in each request
                    if ((is_string($this->client_secret) && $this->client_secret !== '')
                        || ($this->client_id !== null && $this->client_id !== '' && $this->client_id !== $user)
                    ) {
                        $this->_multipleClientAuth = true;
                    }
                    $this->client_id = $user;
                    $this->client_secret = urldecode((string)$password);
                }
            }
            // JWT client authentication (RFC 7523, 2.2): client_id may be omitted, it is the "sub" of the assertion
            $assertionType = self::getRequestValue('client_assertion_type');
            if ($assertionType !== null && $assertionType !== '') {
                $this->_clientAssertionType = $assertionType;
                $this->_clientAssertion = self::getRequestValue('client_assertion');
                $claims = JwtValidator::peekClaims($this->_clientAssertion);
                if (empty($this->client_id) && isset($claims['sub']) && is_string($claims['sub'])) {
                    $this->client_id = $claims['sub'];
                }
            }
        }
    }

    /**
     * Validates the request. The models throw on the first error instead of collecting errors.
     * @inheritdoc
     * @throws Exception
     * @throws RedirectException errors of authorization requests that are reported to the client
     */
    public function validate($attributeNames = null, $clearErrors = true)
    {
        return parent::validate($attributeNames, $clearErrors);
    }

    /**
     * Whether the client authenticates with a client assertion instead of a client secret.
     * @return bool
     */
    public function hasClientAssertion()
    {
        return $this->_clientAssertionType !== null;
    }

    /**
     * Whether the request authenticates the client with a secret or an assertion.
     * @return bool
     */
    public function hasClientCredentials()
    {
        return $this->hasClientAssertion() || (is_string($this->client_secret) && $this->client_secret !== '');
    }

    /**
     * @return JwtValidator
     * @throws \yii\base\InvalidConfigException
     */
    public function getJwtValidator()
    {
        if (!$this->jwtValidator instanceof JwtValidator) {
            $this->jwtValidator = Yii::createObject($this->jwtValidator);
        }
        return $this->jwtValidator;
    }

    /**
     * Whether errors of this model are reported by redirecting the user agent to the client
     * (authorization endpoint) instead of an error response (token endpoint).
     * @return bool
     */
    protected function redirectsErrors()
    {
        return false;
    }

    /**
     * Whether redirected errors are sent in the fragment (implicit grant) instead of the query.
     * @return bool
     */
    protected function errorsInFragment()
    {
        return false;
    }

    /**
     * Throws on the first validation error instead of collecting errors.
     * @param string $type
     * @return never
     * @throws Exception
     */
    public function addError($attribute, $error = '', $type = Exception::INVALID_REQUEST)
    {
        throw new Exception($error, $type);
    }

    /**
     * @param string $error
     * @param string $type
     * @return never
     * @throws Exception
     */
    public function errorServer($error, $type = Exception::INVALID_REQUEST)
    {
        throw new Exception($error, $type);
    }

    /**
     * @param string $error
     * @param string $type
     * @return never
     * @throws Exception
     * @throws RedirectException
     */
    public function errorRedirect($error, $type = Exception::INVALID_REQUEST)
    {
        if (!$this->redirectsErrors()) {
            throw new Exception($error, $type);
        }
        $redirectUri = isset($this->redirect_uri) ? $this->redirect_uri : $this->getDefaultRedirectUri();
        if ($redirectUri) {
            throw new RedirectException(
                $redirectUri,
                $error,
                $type,
                isset($this->state) ? $this->state : null,
                $this->errorsInFragment(),
                isset($this->issuer) ? $this->issuer : null
            );
        } else {
            throw new Exception($error, $type);
        }
    }

    abstract public function getResponseData();

    /**
     * @param string $param
     * @param string|null $header
     * @param Request|null $request
     * @return mixed
     */
    public static function getRequestValue($param, $header = null, $request = null)
    {
        if (is_null($request)) {
            $request = Yii::$app->request;
        }
        if ($header && ($result = $request->headers->get($header))) {
            return $result;
        } else {
            return $request->post($param, $request->get($param));
        }
    }

    /**
     * @return Client
     */
    public function getClient()
    {
        if (is_null($this->_client)) {
            if (empty($this->client_id) || !is_string($this->client_id)) {
                $this->errorServer(Yii::t('conquer/oauth2', 'Unknown client.'), Exception::INVALID_CLIENT);
            }
            if (!$this->_client = Client::findOne(['client_id' => $this->client_id])) {
                $this->errorServer(Yii::t('conquer/oauth2', 'Unknown client.'), Exception::INVALID_CLIENT);
            }
        }
        return $this->_client;
    }

    public function validateClientId()
    {
        $this->getClient();
    }

    /**
     * Authenticates the client (RFC 6749, 2.3) with its secret (body or HTTP Basic) or a JWT assertion.
     * Confidential clients must authenticate. Public clients (no secret and no public key) have no credentials
     * and must not send any.
     * @param string $attribute
     * @return void
     * @throws Exception
     */
    public function validateClientSecret($attribute = 'client_secret')
    {
        if ($this->_multipleClientAuth) {
            $this->errorServer(Yii::t('conquer/oauth2', 'Only one client authentication method may be used.'), Exception::INVALID_REQUEST);
        }
        if ($this->hasClientAssertion()) {
            $this->validateClientAssertion();
            return;
        }
        $client = $this->getClient();
        $secret = $this->$attribute;
        $hasSecret = $secret !== null && $secret !== '';
        if ($client->isPublic()) {
            if ($hasSecret) {
                $this->errorServer(Yii::t('conquer/oauth2', 'The client credentials are invalid.'), Exception::INVALID_CLIENT);
            }
            return;
        }
        if (!$hasSecret) {
            $this->errorServer(Yii::t('conquer/oauth2', 'Client authentication is required.'), Exception::INVALID_CLIENT);
        }
        if (!is_string($secret) || !$client->validateSecret($secret)) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The client credentials are invalid.'), Exception::INVALID_CLIENT);
        }
    }

    /**
     * Revokes all access and refresh tokens of a user issued to a client, after a code or refresh token
     * was used twice (RFC 6749, 4.1.2 and 10.4; RFC 9700, 4.14.2).
     * @param string $clientId
     * @param int|string|null $userId
     * @return void
     */
    protected function revokeTokens($clientId, $userId)
    {
        $condition = ['client_id' => $clientId, 'user_id' => $userId];
        \conquer\oauth2\models\AccessToken::deleteAll($condition);
        \conquer\oauth2\models\RefreshToken::deleteAll($condition);
        Yii::warning("Reused code or refresh token of client $clientId, tokens of user $userId are revoked", __METHOD__);
    }

    /**
     * Rejects public clients, for grants that require client authentication.
     * @return void
     * @throws Exception
     */
    public function requireConfidentialClient()
    {
        if ($this->getClient()->isPublic()) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The grant type is unauthorized for this client.'), Exception::UNAUTHORIZED_CLIENT);
        }
    }

    /**
     * Authenticates the client with a JWT signed with its private key (RFC 7523, sections 2.2 and 3).
     * @return void
     * @throws Exception
     * @throws \yii\base\InvalidConfigException
     */
    public function validateClientAssertion()
    {
        if (is_string($this->client_secret) && $this->client_secret !== '') {
            $this->errorServer(Yii::t('conquer/oauth2', 'Only one client authentication method may be used.'), Exception::INVALID_REQUEST);
        }
        if ($this->_clientAssertionType !== self::CLIENT_ASSERTION_TYPE_JWT) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The client assertion type is not supported.'), Exception::INVALID_CLIENT);
        }
        if (!is_string($this->_clientAssertion) || $this->_clientAssertion === '') {
            $this->errorServer(Yii::t('conquer/oauth2', 'The client assertion is missing.'), Exception::INVALID_REQUEST);
        }
        $client = $this->getClient();
        $publicKey = $client->getPublicKey();
        if ($publicKey === null) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The client credentials are invalid.'), Exception::INVALID_CLIENT);
        }
        try {
            $this->getJwtValidator()->validate($this->_clientAssertion, $publicKey, $client->client_id, $client->client_id);
        } catch (\UnexpectedValueException $e) {
            Yii::info('Invalid client assertion of ' . $client->client_id . ': ' . $e->getMessage(), __METHOD__);
            $this->errorServer(Yii::t('conquer/oauth2', 'The client assertion is invalid.'), Exception::INVALID_CLIENT);
        }
    }

    /**
     * Requested redirect URI must exactly match one of the URIs registered for the client
     * (RFC 6749, section 3.1.2.3; OAuth 2.0 Security BCP).
     * Several URIs can be registered in Client::$redirect_uri separated by whitespace.
     * @param string $attribute
     */
    public function validateRedirectUri($attribute)
    {
        if (!empty($this->$attribute)) {
            if (!is_string($this->$attribute)
                || !in_array($this->$attribute, $this->getClient()->getRedirectUris(), true)
            ) {
                $this->errorServer(Yii::t('conquer/oauth2', 'The redirect URI provided is missing or does not match.'), Exception::INVALID_REQUEST);
            }
        }
    }

    /**
     * Validates redirect_uri of an authorization request. When it is omitted, the client must have
     * exactly one registered redirect URI, which is used instead.
     * @param string $attribute
     */
    public function validateAuthorizationRedirectUri($attribute)
    {
        if (empty($this->$attribute)) {
            if (!$this->$attribute = $this->getDefaultRedirectUri()) {
                $this->errorServer(Yii::t('conquer/oauth2', 'The redirect URI provided is missing or does not match.'), Exception::INVALID_REQUEST);
            }
            $this->_redirectUriFromClient = true;
        } else {
            $this->validateRedirectUri($attribute);
        }
    }

    /**
     * @var bool whether redirect_uri was not provided in the request and taken from the client
     */
    protected $_redirectUriFromClient = false;

    /**
     * Returns the registered redirect URI when the client has exactly one, null otherwise.
     * @return string|null
     */
    public function getDefaultRedirectUri()
    {
        $uris = $this->getClient()->getRedirectUris();
        return count($uris) === 1 ? $uris[0] : null;
    }

    /**
     * Checks that the client is allowed to use the grant type.
     * Client::$grant_type is a space-delimited list of permitted grant types, empty means all.
     * @param string $grantType
     */
    public function checkGrantType($grantType)
    {
        $allowed = trim((string)$this->getClient()->grant_type);
        if ($allowed !== '' && !in_array($grantType, preg_split('/\s+/', $allowed), true)) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The grant type is unauthorized for this client.'), Exception::UNAUTHORIZED_CLIENT);
        }
    }

    /**
     * Checks at the authorization endpoint that the client may use the grant type; the error is redirected.
     * @param string $grantType "authorization_code" or "implicit"
     * @return void
     * @throws Exception
     */
    public function checkResponseGrantType($grantType)
    {
        $allowed = self::splitScope((string)$this->getClient()->grant_type);
        if ($allowed && !in_array($grantType, $allowed, true)) {
            $this->errorRedirect(Yii::t('conquer/oauth2', 'The grant type is unauthorized for this client.'), Exception::UNAUTHORIZED_CLIENT);
        }
    }

    public function validateScope($attribute)
    {
        if (!$this->checkSets($this->$attribute, $this->client->scope)) {
            $this->errorRedirect(Yii::t('conquer/oauth2', 'The requested scope is invalid, unknown, or malformed.'), Exception::INVALID_SCOPE);
        }
    }

    /**
     * Checks if everything in required set is contained in available set.
     *
     * @param string|array $requiredSet
     * @param string|array $availableSet
     * @return boolean
     */
    protected function checkSets($requiredSet, $availableSet)
    {
        return count(array_diff(self::splitScope($requiredSet), self::splitScope($availableSet))) === 0;
    }

    /**
     * Splits a space-delimited scope string into a list; null and empty strings give an empty list.
     * @param string|array|null $scope
     * @return string[]
     */
    public static function splitScope($scope)
    {
        if (is_array($scope)) {
            return array_values(array_filter($scope, static function ($item) {
                return is_string($item) && $item !== '';
            }));
        }
        return preg_split('/\s+/', trim((string)$scope), -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }
}
