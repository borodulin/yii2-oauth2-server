<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use conquer\oauth2\services\AccessTokenService;
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
     * @var string the HTTP authentication realm
     */
    public $realm;

    /**
     * @var AccessTokenService
     */
    private $_accessTokenService;

    public function __construct(AccessTokenService $accessTokenService, array $config = [])
    {
        $this->_accessTokenService = $accessTokenService;
        parent::__construct($config);
    }

    /**
     * @param \yii\web\User $user
     * @param \yii\web\Request $request
     * @param \yii\web\Response $response
     * @return mixed
     * @throws UnauthorizedHttpException
     * @throws \yii\base\InvalidConfigException
     */
    public function authenticate($user, $request, $response)
    {
        $oauth2 = OAuth2::instance();
        $oauth2->request = $request;

        $accessToken = $this->_accessTokenService->accessToken;

        /** @var IdentityInterface $identityClass */
        $identityClass = $oauth2->identityClass;

        $identity = $identityClass::findIdentity($accessToken->user_id);

        if (!$identity) {
            throw new UnauthorizedHttpException('User is not found.');
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
     * @param $response
     * @throws UnauthorizedHttpException
     */
    public function handleFailure($response)
    {
        throw new UnauthorizedHttpException('You are requesting with an invalid credential.');
    }
}
