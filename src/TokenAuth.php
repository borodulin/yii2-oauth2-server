<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use conquer\oauth2\models\AccessToken;
use conquer\oauth2\request\AccessTokenExtractor;
use Yii;
use yii\base\Controller;
use yii\filters\auth\AuthMethod;
use yii\web\ForbiddenHttpException;
use yii\web\IdentityInterface;
use yii\web\Response;
use yii\web\UnauthorizedHttpException;

/**
 * TokenAuth is an action filter that supports the authentication method based on the OAuth2 Access Token.
 *
 * You may use TokenAuth by attaching it as a behavior to a controller or module, like the following:
 *
 * ```php
 * public function behaviors()
 * {
 *     return [
 *         'tokenAuth' => [
 *             'class' => \conquer\oauth2\TokenAuth::className(),
 *         ],
 *     ];
 * }
 * ```
 *
 * @author Andrey Borodulin
 */
class TokenAuth extends AuthMethod
{
    /**
     * @var AccessToken|null
     */
    private $_accessToken;

    /**
     * @var string the HTTP authentication realm
     */
    public $realm;

    /**
     * @var string|null the class name of the [[identity]] object, defaults to [[\yii\web\User::$identityClass]].
     */
    public $identityClass;

    /**
     * @var array scopes that need to be on token.
     */
    public $scopes = [];

    /**
     * @var bool whether the access_token query parameter is accepted (RFC 6750, 2.3: SHOULD NOT be used)
     */
    public $allowQueryToken = false;

    /**
     * @param \yii\web\User $user
     * @param \yii\web\Request $request
     * @param \yii\web\Response $response
     * @return mixed
     * @throws Exception
     * @throws UnauthorizedHttpException
     */
    public function authenticate($user, $request, $response)
    {
        try {
            $accessToken = $this->getAccessToken();
        } catch (Exception $e) {
            // malformed request (RFC 6750, 3.1)
            $this->setChallenge($response, Exception::INVALID_REQUEST, $e->getMessage());
            throw $e;
        }
        if ($accessToken === null) {
            // no credentials: let AuthMethod handle optional actions, CompositeAuth and the 401 challenge
            return null;
        }

        if (!$this->checkScopes($this->scopes, $accessToken->scope)) {
            $message = Yii::t('conquer/oauth2', 'The access token does not have required scopes.');
            $this->setChallenge($response, 'insufficient_scope', $message, BaseModel::splitScope($this->scopes));
            throw new ForbiddenHttpException($message);
        }

        /** @var IdentityInterface $identityClass */
        $identityClass = is_null($this->identityClass) ? $user->identityClass : $this->identityClass;

        $identity = $identityClass::findIdentity($accessToken->user_id);

        if (empty($identity)) {
            $this->invalidToken($response, Yii::t('conquer/oauth2', 'User is not found.'));
        }

        $user->setIdentity($identity);

        return $identity;
    }

    /**
     * Checks if everything in required set is contained in available set.
     *
     * @param string|array $requiredSet
     * @param string|array $availableSet
     * @return boolean
     */
    protected function checkScopes($requiredSet, $availableSet)
    {
        return count(array_diff(BaseModel::splitScope($requiredSet), BaseModel::splitScope($availableSet))) === 0;
    }

    /**
     * @param Response $response
     */
    public function challenge($response)
    {
        $this->setChallenge($response);
    }

    /**
     * Sets the WWW-Authenticate header (RFC 6750, 3).
     * @param Response $response
     * @param string|null $error invalid_request, invalid_token or insufficient_scope
     * @param string|null $description
     * @param string[] $scopes
     * @return void
     */
    protected function setChallenge($response, $error = null, $description = null, array $scopes = [])
    {
        $params = ['realm' => $this->getRealm()];
        if ($error !== null) {
            $params['error'] = $error;
        }
        if ($description !== null && $description !== '') {
            $params['error_description'] = $description;
        }
        if ($scopes) {
            $params['scope'] = implode(' ', $scopes);
        }
        $parts = [];
        foreach ($params as $name => $value) {
            $parts[] = $name . '="' . addcslashes((string)$value, '"\\') . '"';
        }
        $response->getHeaders()->set('WWW-Authenticate', 'Bearer ' . implode(', ', $parts));
    }

    /**
     * @return string
     */
    protected function getRealm()
    {
        if (!empty($this->realm)) {
            return $this->realm;
        }
        /** @var Controller|null $owner */
        $owner = $this->owner;
        return $owner instanceof Controller ? $owner->getUniqueId() : Yii::$app->id;
    }

    /**
     * @param Response $response
     * @param string $message
     * @return never
     * @throws UnauthorizedHttpException
     */
    protected function invalidToken($response, $message)
    {
        $this->setChallenge($response, 'invalid_token', $message);
        throw new UnauthorizedHttpException($message);
    }

    /**
     * @inheritdoc
     */
    public function handleFailure($response)
    {
        throw new UnauthorizedHttpException(Yii::t('conquer/oauth2', 'You are requesting with an invalid credential.'));
    }

    /**
     * @return AccessToken|null null when the request contains no access token
     * @throws Exception
     * @throws UnauthorizedHttpException
     */
    protected function getAccessToken()
    {
        if (is_null($this->_accessToken)) {
            $tokenExtractor = Yii::createObject(AccessTokenExtractor::class, [Yii::$app->getRequest(), $this->allowQueryToken]);

            $token = $tokenExtractor->extract(false);
            if ($token === null) {
                return null;
            }
            if (!$accessToken = AccessToken::findOne(['access_token' => $token])) {
                $this->invalidToken(Yii::$app->getResponse(), Yii::t('conquer/oauth2', 'The access token provided is invalid.'));
            }
            if ($accessToken->expires < time()) {
                $this->invalidToken(Yii::$app->getResponse(), Yii::t('conquer/oauth2', 'The access token provided has expired.'));
            }
            $this->_accessToken = $accessToken;
        }
        return $this->_accessToken;
    }
}
