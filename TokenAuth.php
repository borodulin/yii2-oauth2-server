<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use conquer\oauth2\models\AccessToken;
use Yii;
use yii\base\Controller;
use yii\filters\auth\AuthMethod;
use yii\web\Response;
use yii\web\UnauthorizedHttpException;
use yii\web\IdentityInterface;

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
     */
    public function handleFailure($response)
    {
        throw new Exception('You are requesting with an invalid credential.');
    }

    /**
     * @return AccessToken
     * @throws Exception
     * @throws UnauthorizedHttpException
     */
    protected function getAccessToken()
    {
        if (is_null($this->_accessToken)) {
            $request = Yii::$app->request;

            $authHeader = $request->getHeaders()->get('Authorization');

            $postToken = $request->post('access_token');
            $getToken = $request->get('access_token');

            // Check that exactly one method was used
            $methodsCount = isset($authHeader) + isset($postToken) + isset($getToken);
            if ($methodsCount > 1) {
                throw new Exception('Only one method may be used to authenticate at a time (Auth header, POST or GET).');
            } elseif ($methodsCount == 0) {
                throw new Exception('The access token was not found.');
            }
            // HEADER: Get the access token from the header
            if ($authHeader) {
                if (preg_match('/^Bearer\\s+(.*?)$/', $authHeader, $matches)) {
                    $token = $matches[1];
                } else {
                    throw new Exception('Malformed auth header.');
                }
            } else {
                // POST: Get the token from POST data
                if ($postToken) {
                    if (! $request->isPost) {
                        throw new Exception('When putting the token in the body, the method must be POST.');
                    }
                    // IETF specifies content-type. NB: Not all webservers populate this _SERVER variable
                    if (strpos($request->contentType, 'application/x-www-form-urlencoded') !== 0) {
                        throw new Exception('The content type for POST requests must be "application/x-www-form-urlencoded"');
                    }
                    $token = $postToken;
                } else {
                    $token = $getToken;
                }
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
