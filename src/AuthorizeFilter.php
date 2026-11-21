<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use Yii;
use yii\base\ActionFilter;

/**
 * Authorization endpoint filter (RFC 6749, 3.1).
 *
 * Validates the authorization request and keeps it in the session while the user logs in.
 * The user must approve the request: show a consent page with [[getAuthorizationRequest()]] and call
 * [[finishAuthorization()]] on POST (protected by Yii's CSRF validation). Requests of trusted clients can be
 * approved automatically with [[autoApprove]].
 *
 * @author Andrey Borodulin
 */
class AuthorizeFilter extends ActionFilter
{
    /**
     * @var BaseModel|null
     */
    private $_responseType;

    /**
     * @var bool whether the authorization has been finished in this request
     */
    private $_finished = false;

    /**
     * @var array<string, string|array<string, mixed>>
     */
    public $responseTypes = [
        'token' => 'conquer\oauth2\responsetypes\Implicit',
        'code' => 'conquer\oauth2\responsetypes\Authorization',
    ];

    /**
     * @var boolean
     */
    public $allowImplicit = false;

    /**
     * @var bool|callable whether requests are approved without asking the user, e.g. for first-party clients:
     * `function (\conquer\oauth2\BaseModel $request): bool`, the client is `$request->client`.
     * When approved automatically, a logged-in user is redirected back to the client right away,
     * so never enable it for third-party clients: any web page could then obtain codes for its visitors.
     */
    public $autoApprove = false;

    /**
     * @var string|null session key of the stored authorization request, null disables storing
     */
    public $storeKey = 'ear6kme7or19rnfldtmwsxgzxsrmngqw';

    /**
     * @var int seconds a stored authorization request stays valid
     */
    public $requestLifetime = 600;

    /**
     * @return void
     */
    public function init()
    {
        Translations::register();
        parent::init();
        if (!$this->allowImplicit) {
            unset($this->responseTypes['token']);
        }
    }

    /**
     * Validates the authorization request and stores it in the session, so that the user can log in,
     * also with a third party provider, before the request is finished.
     * A request without response_type continues the stored request, if any.
     * @param \yii\base\Action $action
     * @return bool
     * @throws Exception
     */
    public function beforeAction($action)
    {
        $responseType = BaseModel::getRequestValue('response_type');
        if (($responseType === null || $responseType === '') && $this->getStoredRequest() !== null) {
            return true;
        }
        if (!$responseType || !is_string($responseType)) {
            throw new Exception(Yii::t('conquer/oauth2', 'Invalid or missing response type.'));
        }
        if (!isset($this->responseTypes[$responseType])) {
            throw new Exception(Yii::t('conquer/oauth2', 'An unsupported response type was requested.'), Exception::UNSUPPORTED_RESPONSE_TYPE);
        }
        /** @var BaseModel $model */
        $model = Yii::createObject($this->responseTypes[$responseType]);
        // the raw request parameters, before validation fills in defaults such as the redirect URI
        $params = $model->getAttributes($model->safeAttributes());
        try {
            $model->validate();
        } catch (RedirectException $e) {
            Yii::$app->response->redirect($e->getRedirectUri());
            return false;
        }
        $this->_responseType = $model;

        if ($this->canStore()) {
            Yii::$app->session->set($this->storeKey, [
                'type' => $responseType,
                'params' => $params,
                'time' => time(),
            ]);
        }

        return true;
    }

    /**
     * Finishes requests that are approved automatically, when the user is logged in.
     * @param \yii\base\Action $action
     * @param mixed $result
     * @return mixed
     */
    public function afterAction($action, $result)
    {
        if ($this->_finished || Yii::$app->user->isGuest || !$this->getIsOauthRequest()) {
            return $result;
        }
        try {
            $request = $this->getAuthorizationRequest();
        } catch (RedirectException $e) {
            $this->clearStoredRequest();
            Yii::$app->response->redirect($e->getRedirectUri());
            return null;
        }
        if ($this->isAutoApproved($request)) {
            $this->finishAuthorization();
            return null;
        }
        return $result;
    }

    /**
     * Returns the current authorization request, for the consent page: the client is `$request->client`,
     * the requested scope is `$request->scope`.
     * @return BaseModel
     * @throws Exception when there is no authorization request or it has expired
     */
    public function getAuthorizationRequest()
    {
        if ($this->_responseType === null) {
            $stored = $this->getStoredRequest();
            if ($stored === null) {
                throw new Exception(Yii::t('conquer/oauth2', 'Invalid server state or the User Session has expired.'), Exception::INVALID_REQUEST);
            }
            /** @var BaseModel $model */
            $model = Yii::createObject($this->responseTypes[$stored['type']]);
            $model->setAttributes($stored['params']);
            // the client may have been changed or removed since the request was stored
            $model->validate();
            $this->_responseType = $model;
        }
        return $this->_responseType;
    }

    /**
     * @return BaseModel
     * @throws Exception
     * @deprecated use getAuthorizationRequest()
     */
    protected function getResponseType()
    {
        return $this->getAuthorizationRequest();
    }

    /**
     * Finishes the authorization: redirects the user agent to the client with a code or token,
     * or with the access_denied error when the user declined or is not logged in.
     *
     * Unless the request is approved automatically, it must be called on a POST request (the consent form),
     * so that Yii's CSRF validation protects it.
     *
     * @param bool $approved whether the user approved the request
     * @return void
     * @throws Exception
     */
    public function finishAuthorization($approved = true)
    {
        try {
            $responseType = $this->getAuthorizationRequest();
        } catch (RedirectException $e) {
            $this->clearStoredRequest();
            Yii::$app->response->redirect($e->getRedirectUri());
            return;
        }
        $this->clearStoredRequest();
        $this->_finished = true;

        try {
            if (!$approved || Yii::$app->user->isGuest) {
                $responseType->errorRedirect(Yii::t('conquer/oauth2', 'The User denied access to your application.'), Exception::ACCESS_DENIED);
            }
            if (!$this->isAutoApproved($responseType) && !Yii::$app->request->getIsPost()) {
                throw new Exception(Yii::t('conquer/oauth2', 'The authorization must be approved with a POST request.'));
            }
            $parts = $responseType->getResponseData();
        } catch (RedirectException $e) {
            Yii::$app->response->redirect($e->getRedirectUri());
            return;
        }

        $redirectUri = http_build_url($responseType->redirect_uri, $parts, HTTP_URL_JOIN_QUERY | HTTP_URL_STRIP_FRAGMENT);

        if (isset($parts['fragment'])) {
            $redirectUri .= '#' . $parts['fragment'];
        }

        Yii::$app->response->redirect($redirectUri);
    }

    /**
     * Whether there is an unfinished authorization request.
     * @return boolean
     */
    public function getIsOauthRequest()
    {
        if ($this->_finished) {
            return false;
        }
        return $this->_responseType !== null || $this->getStoredRequest() !== null;
    }

    /**
     * @param BaseModel $request
     * @return bool
     */
    protected function isAutoApproved($request)
    {
        if (is_callable($this->autoApprove)) {
            return (bool)call_user_func($this->autoApprove, $request);
        }
        return $this->autoApprove === true;
    }

    /**
     * @return bool
     */
    protected function canStore()
    {
        return !empty($this->storeKey) && Yii::$app->has('session');
    }

    /**
     * Returns the stored request when it is valid and not expired.
     * @return array{type: string, params: array<string, mixed>, time: int}|null
     */
    protected function getStoredRequest()
    {
        if (!$this->canStore()) {
            return null;
        }
        $data = Yii::$app->session->get($this->storeKey);
        if (!is_array($data) || !isset($data['type'], $data['params'], $data['time'])
            || !is_string($data['type']) || !isset($this->responseTypes[$data['type']])
            || !is_array($data['params']) || !is_int($data['time'])
            || $data['time'] < time() - $this->requestLifetime
        ) {
            return null;
        }
        return $data;
    }

    /**
     * @return void
     */
    protected function clearStoredRequest()
    {
        if ($this->canStore()) {
            Yii::$app->session->remove($this->storeKey);
        }
    }
}
