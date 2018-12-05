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
     * @var AccessToken
     */
    private $_accessToken;

    /**
     * @var string the HTTP authentication realm
     */
    public $realm;

    /**
     * @var string the class name of the [[identity]] object.
     */
    public $identityClass;

    /**
     * @var array scopes that need to be on token.
     */
    public $scopes = [];

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
        $accessToken = $this->getAccessToken();

        if (!$this->checkScopes($this->scopes, $accessToken->scope)) {
            throw new UnauthorizedHttpException(Yii::t('oauth2', 'The access token does not have required scopes.'));
        }

        /** @var IdentityInterface $identityClass */
        $identityClass = is_null($this->identityClass) ? $user->identityClass : $this->identityClass;

        $identity = $identityClass::findIdentity($accessToken->user_id);

        if (empty($identity)) {
            throw new Exception(Yii::t('oauth2', 'User is not found.'), Exception::ACCESS_DENIED);
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
        if (!is_array($requiredSet)) {
            $requiredSet = explode(' ', trim($requiredSet));
        }
        if (!is_array($availableSet)) {
            $availableSet = explode(' ', trim($availableSet));
        }
        return (count(array_diff($requiredSet, $availableSet)) == 0);
    }

    /**
     * @param Response $response
     */
    public function challenge($response)
    {
        /** @var Controller $owner */
        $owner = $this->owner;
        $realm = empty($this->realm) ? $owner->getUniqueId() : $this->realm;
        $response->getHeaders()->set('WWW-Authenticate', "Bearer realm=\"{$realm}\"");
    }

    /**
     * @inheritdoc
     */
    public function handleFailure($response)
    {
        throw new Exception(Yii::t('oauth2', 'You are requesting with an invalid credential.'));
    }

    /**
     * @return AccessToken
     * @throws Exception
     * @throws UnauthorizedHttpException
     */
    protected function getAccessToken()
    {
        if (is_null($this->_accessToken)) {
            $tokenExtractor = Yii::createObject(AccessTokenExtractor::class);

            if (!$accessToken = AccessToken::findOne(['access_token' => $tokenExtractor->extract()])) {
                throw new UnauthorizedHttpException(Yii::t('oauth2', 'The access token provided is invalid.'));
            }
            if ($accessToken->expires < time()) {
                throw new UnauthorizedHttpException(Yii::t('oauth2', 'The access token provided has expired.'));
            }
            $this->_accessToken = $accessToken;
        }
        return $this->_accessToken;
    }
}
