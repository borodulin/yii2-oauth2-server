<?php

namespace conquer\oauth2;

use conquer\oauth2\models\Client;
use Yii;
use yii\base\Model;
use yii\helpers\ArrayHelper;
use yii\web\Request;

/**
 * @property Client $client
 */
abstract class BaseModel extends Model
{
    /**
     * @var Client
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
        parent::init();
        $headers = [
            'client_id' => 'PHP_AUTH_USER',
            'client_secret' => 'PHP_AUTH_PW',
        ];

        foreach ($this->safeAttributes() as $attribute) {
            $this->$attribute = self::getRequestValue($attribute, ArrayHelper::getValue($headers, $attribute));
        }
    }

    public function addError($attribute, $error = '', $type = Exception::INVALID_REQUEST)
    {
        throw new Exception($error, $type);
    }

    public function errorServer($error, $type = Exception::INVALID_REQUEST)
    {
        throw new Exception($error, $type);
    }

    public function errorRedirect($error, $type = Exception::INVALID_REQUEST)
    {
        $redirectUri = isset($this->redirect_uri) ? $this->redirect_uri : $this->getDefaultRedirectUri();
        if ($redirectUri) {
            throw new RedirectException($redirectUri, $error, $type, isset($this->state) ? $this->state : null);
        } else {
            throw new Exception($error, $type);
        }
    }

    abstract public function getResponseData();

    public static function getRequestValue($param, $header = null, Request $request = null)
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

    public function validateClientSecret($attribute)
    {
        $secret = $this->$attribute;
        if (!is_string($secret) || $secret === ''
            || !Yii::$app->security->compareString((string)$this->getClient()->client_secret, $secret)
        ) {
            $this->addError($attribute, Yii::t('conquer/oauth2', 'The client credentials are invalid.'), Exception::UNAUTHORIZED_CLIENT);
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
                $this->errorServer(Yii::t('conquer/oauth2', 'The redirect URI provided is missing or does not match.'), Exception::REDIRECT_URI_MISMATCH);
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
                $this->errorServer(Yii::t('conquer/oauth2', 'The redirect URI provided is missing or does not match.'), Exception::REDIRECT_URI_MISMATCH);
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
        if (!is_array($requiredSet)) {
            $requiredSet = explode(' ', trim($requiredSet));
        }
        if (!is_array($availableSet)) {
            $availableSet = explode(' ', trim($availableSet));
        }
        return (count(array_diff($requiredSet, $availableSet)) == 0);
    }
}
