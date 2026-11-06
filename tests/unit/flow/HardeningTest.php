<?php

namespace tests\unit\flow;

use conquer\oauth2\AuthorizeFilter;
use conquer\oauth2\Exception;
use conquer\oauth2\RedirectException;
use conquer\oauth2\TokenAction;
use conquer\oauth2\TokenAuth;
use conquer\oauth2\granttypes\Authorization;
use conquer\oauth2\granttypes\ClientCredentials;
use conquer\oauth2\granttypes\RefreshToken;
use conquer\oauth2\models\AccessToken;
use tests\OAuthTestCase;
use tests\TestIdentity;
use Yii;
use yii\base\Component;

/**
 * In-memory session for tests.
 */
class ArraySession extends Component
{
    private $data = [];
    public function set($key, $value) { $this->data[$key] = $value; }
    public function get($key) { return isset($this->data[$key]) ? $this->data[$key] : null; }
    public function has($key) { return isset($this->data[$key]); }
    public function remove($key) { unset($this->data[$key]); }
}

class HardeningTest extends OAuthTestCase
{
    protected function _after()
    {
        unset($_SERVER['REQUEST_METHOD']);
        parent::_after();
    }

    public function testHttpBasicClientAuthentication()
    {
        Yii::$app->request->headers->set('Authorization', 'Basic ' . base64_encode('app:secret'));
        $model = $this->model(ClientCredentials::class, ['grant_type' => 'client_credentials']);
        $this->assertTrue($model->validate());
        $this->assertSame('app', $model->client_id);

        Yii::$app->request->headers->set('Authorization', 'Basic ' . base64_encode('app:wrong'));
        $model = $this->model(ClientCredentials::class, ['grant_type' => 'client_credentials']);
        $this->assertOAuthError(Exception::UNAUTHORIZED_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testTokenEndpointErrorsAreNotRedirects()
    {
        $model = $this->model(ClientCredentials::class, [
            'grant_type' => 'client_credentials', 'client_id' => 'app', 'client_secret' => 'secret', 'scope' => 'admin',
        ]);
        try {
            $model->validate();
            $this->fail('invalid scope must be rejected');
        } catch (Exception $e) {
            $this->assertNotInstanceOf(RedirectException::class, $e);
            $this->assertSame(Exception::INVALID_SCOPE, $e->getName());
            $this->assertNull(Yii::$app->response->headers->get('Location'));
        }
    }

    public function testScopesWithExtraSpacesAreAccepted()
    {
        $model = $this->model(ClientCredentials::class, [
            'grant_type' => 'client_credentials', 'client_id' => 'app', 'client_secret' => 'secret', 'scope' => ' read  write ',
        ]);
        $this->assertTrue($model->validate());
    }

    public function testTokenWithoutScopeAuthenticatesOnPhp81()
    {
        $token = AccessToken::createAccessToken(['client_id' => 'app', 'user_id' => 42, 'expires' => time() + 60]);
        Yii::$app->request->headers->set('Authorization', 'Bearer ' . $token->access_token);
        set_error_handler(function ($code, $message) {
            throw new \ErrorException($message, 0, $code);
        });
        try {
            $identity = (new TokenAuth())->authenticate(Yii::$app->user, Yii::$app->request, Yii::$app->response);
        } finally {
            restore_error_handler();
        }
        $this->assertSame(42, $identity->getId());
    }

    public function testMissingTokenIsNotAuthenticatedInsteadOfError()
    {
        $this->assertNull((new TokenAuth())->authenticate(Yii::$app->user, Yii::$app->request, Yii::$app->response));
    }

    public function testStoredAuthorizationRequestIsUsedOnce()
    {
        Yii::$app->set('session', ArraySession::class);
        Yii::$app->request->setQueryParams(['response_type' => 'code', 'client_id' => 'app']);
        $filter = new AuthorizeFilter();
        $filter->beforeAction(null);
        $this->assertTrue($filter->getIsOauthRequest());

        Yii::$app->user->setIdentity(new TestIdentity(['id' => 42]));
        $filter->finishAuthorization();
        $this->assertStringStartsWith('https://app.example.com/cb?code=', Yii::$app->response->headers->get('Location'));
        $this->assertFalse($filter->getIsOauthRequest(), 'a later login must not finish the old OAuth request again');
    }

    private function tokenAction()
    {
        return new TokenAction('token', new \yii\web\Controller('auth', Yii::$app));
    }

    public function testTokenEndpointRequiresPost()
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        Yii::$app->request->setQueryParams(['grant_type' => 'client_credentials', 'client_id' => 'app', 'client_secret' => 'secret']);
        $this->assertOAuthError(Exception::INVALID_REQUEST, function () {
            $this->tokenAction()->run();
        });
    }

    public function testCredentialsInQueryStringAreRejected()
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        Yii::$app->request->setBodyParams(['grant_type' => 'client_credentials', 'client_id' => 'app']);
        Yii::$app->request->setQueryParams(['client_secret' => 'secret']);
        $this->assertOAuthError(Exception::INVALID_REQUEST, function () {
            $this->tokenAction()->run();
        });
    }

    public function testTokenResponseIsNotCacheable()
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        Yii::$app->request->setBodyParams(['grant_type' => 'client_credentials', 'client_id' => 'app', 'client_secret' => 'secret']);
        Yii::$app->request->setQueryParams([]);
        $this->tokenAction()->run();
        $this->assertNotEmpty(Yii::$app->response->data['access_token']);
        $this->assertSame('no-store', Yii::$app->response->headers->get('Cache-Control'));
        $this->assertSame('no-cache', Yii::$app->response->headers->get('Pragma'));
    }

    public function testCodeCannotBeRedeemedTwiceConcurrently()
    {
        $code = $this->createCode('app');
        $params = ['grant_type' => 'authorization_code', 'client_id' => 'app', 'client_secret' => 'secret', 'code' => $code->authorization_code];
        $first = $this->model(Authorization::class, $params);
        $second = $this->model(Authorization::class, $params);
        $this->assertTrue($first->validate());
        $this->assertTrue($second->validate());
        $this->assertNotEmpty($first->getResponseData()['access_token']);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($second) {
            $second->getResponseData();
        });
    }

    public function testRefreshTokenCannotBeUsedTwiceConcurrently()
    {
        $token = $this->createRefreshToken('app');
        $params = ['grant_type' => 'refresh_token', 'client_id' => 'app', 'client_secret' => 'secret', 'refresh_token' => $token->refresh_token];
        $first = $this->model(RefreshToken::class, $params);
        $second = $this->model(RefreshToken::class, $params);
        $this->assertTrue($first->validate());
        $this->assertTrue($second->validate());
        $this->assertNotEmpty($first->getResponseData()['access_token']);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($second) {
            $second->getResponseData();
        });
    }
}
