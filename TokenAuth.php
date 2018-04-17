<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use conquer\oauth2\models\AccessToken;
use yii\base\Controller;
use yii\filters\auth\AuthMethod;
use yii\web\IdentityInterface;
use yii\web\MethodNotAllowedHttpException;
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
     * @throws \yii\base\InvalidConfigException
     */
    public function init()
    {
        if ($this->identityClass === null) {
            $this->identityClass = OAuth2::instance()->identityClass;
        }
    }

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

        /** @var IdentityInterface $identityClass */
        $identityClass = is_null($this->identityClass) ? $user->identityClass : $this->identityClass;

        $identity = $identityClass::findIdentity($accessToken->user_id);

        if (empty($identity)) {
            throw new Exception('User is not found.', Exception::ACCESS_DENIED);
        }

        $user->setIdentity($identity);

        return $identity;
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
     * @throws Exception
     */
    public function handleFailure($response)
    {
        throw new Exception('You are requesting with an invalid credential.');
    }

    /**
     * @return AccessToken
     * @throws Exception
     * @throws MethodNotAllowedHttpException
     * @throws UnauthorizedHttpException
     */
    protected function getAccessToken()
    {
        if (is_null($this->_accessToken)) {
            $request = $this->request;

            if ($authHeader = $request->getHeaders()->get('Authorization')) {
                if (preg_match('/^Bearer\\s+(.*?)$/', $authHeader, $matches)) {
                    $token = $matches[1];
                } else {
                    throw new Exception('Malformed auth header.');
                }
            } elseif ($request->isPost) {
                $token = $request->post('access_token');
            } elseif ($request->isGet) {
                $token = $request->get('access_token');
            } else {
                throw new MethodNotAllowedHttpException();
            }

            if (!$accessToken = AccessToken::findOne(['access_token' => $token])) {
                throw new UnauthorizedHttpException('The access token provided is invalid.');
            }
            if ($accessToken->expires < time()) {
                throw new UnauthorizedHttpException('The access token provided has expired.');
            }
            $this->_accessToken = $accessToken;
        }
        return $this->_accessToken;
    }
}
