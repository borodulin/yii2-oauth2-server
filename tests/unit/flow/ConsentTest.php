<?php

namespace tests\unit\flow;

use conquer\oauth2\AuthorizeFilter;
use conquer\oauth2\Exception;
use conquer\oauth2\models\AuthorizationCode;
use conquer\oauth2\responsetypes\Authorization;
use tests\ArraySession;
use tests\OAuthTestCase;
use tests\TestIdentity;
use Yii;
use yii\base\Action;
use yii\web\Controller;

/**
 * User consent and the authorization request stored in the session.
 */
class ConsentTest extends OAuthTestCase
{
    protected function _before()
    {
        parent::_before();
        Yii::$app->set('session', ArraySession::class);
        $_SERVER['REQUEST_METHOD'] = 'GET';
    }

    protected function _after()
    {
        unset($_SERVER['REQUEST_METHOD']);
        parent::_after();
    }

    private function action()
    {
        return new Action('authorize', new Controller('site', Yii::$app));
    }

    private function request(array $params)
    {
        Yii::$app->request->setQueryParams($params);
        Yii::$app->request->setBodyParams([]);
    }

    private function login()
    {
        Yii::$app->user->setIdentity(new TestIdentity(['id' => 42]));
    }

    public function testLoggedInUserIsNotAuthorizedWithoutConsent()
    {
        $this->login();
        $this->request(['response_type' => 'code', 'client_id' => 'app']);
        $filter = new AuthorizeFilter();
        $this->assertTrue($filter->beforeAction($this->action()));
        $this->assertSame('consent page', $filter->afterAction($this->action(), 'consent page'));
        $this->assertNull(Yii::$app->response->headers->get('Location'));
        $this->assertSame(0, (int)AuthorizationCode::find()->count());
    }

    public function testFinishOnGetIsRejectedWithoutAutoApproval()
    {
        $this->login();
        $this->request(['response_type' => 'code', 'client_id' => 'app']);
        $filter = new AuthorizeFilter();
        $filter->beforeAction($this->action());
        $this->assertOAuthError(Exception::INVALID_REQUEST, function () use ($filter) {
            $filter->finishAuthorization();
        });
    }

    public function testConsentPostIssuesOneCode()
    {
        $this->request(['response_type' => 'code', 'client_id' => 'app', 'scope' => 'read', 'state' => 's']);
        (new AuthorizeFilter())->beforeAction($this->action());

        // the consent form is posted without the OAuth parameters, the request comes from the session
        $this->login();
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $this->request([]);
        $filter = new AuthorizeFilter();
        $this->assertTrue($filter->beforeAction($this->action()));
        $request = $filter->getAuthorizationRequest();
        $this->assertSame('app', $request->client->client_id);
        $this->assertSame('read', $request->scope);
        $filter->finishAuthorization(true);
        $filter->afterAction($this->action(), null);

        $location = Yii::$app->response->headers->get('Location');
        $this->assertStringStartsWith('https://app.example.com/cb?code=', $location);
        $this->assertStringContainsString('state=s', $location);
        $this->assertSame(1, (int)AuthorizationCode::find()->count(), 'afterAction must not issue a second code');
        $this->assertFalse($filter->getIsOauthRequest());
    }

    public function testDeclinedConsentRedirectsAccessDenied()
    {
        $this->login();
        $this->request(['response_type' => 'code', 'client_id' => 'app', 'state' => 's']);
        $filter = new AuthorizeFilter();
        $filter->beforeAction($this->action());
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $filter->finishAuthorization(false);
        $this->assertStringStartsWith('https://app.example.com/cb?error=access_denied', Yii::$app->response->headers->get('Location'));
        $this->assertSame(0, (int)AuthorizationCode::find()->count());
    }

    public function testAutoApprovedClientIsRedirectedRightAway()
    {
        $this->login();
        $this->request(['response_type' => 'code', 'client_id' => 'app']);
        $filter = new AuthorizeFilter(['autoApprove' => function ($request) {
            return $request->client->client_id === 'app';
        }]);
        $filter->beforeAction($this->action());
        $this->assertNull($filter->afterAction($this->action(), 'page'));
        $this->assertStringStartsWith('https://app.example.com/cb?code=', Yii::$app->response->headers->get('Location'));
        $this->assertSame(1, (int)AuthorizationCode::find()->count());
    }

    public function testStoredRequestExpires()
    {
        $this->request(['response_type' => 'code', 'client_id' => 'app']);
        (new AuthorizeFilter())->beforeAction($this->action());
        $data = Yii::$app->session->get('ear6kme7or19rnfldtmwsxgzxsrmngqw');
        $data['time'] -= 601;
        Yii::$app->session->set('ear6kme7or19rnfldtmwsxgzxsrmngqw', $data);

        $this->request([]);
        $filter = new AuthorizeFilter();
        $this->assertFalse($filter->getIsOauthRequest());
        $this->assertOAuthError(Exception::INVALID_REQUEST, function () use ($filter) {
            $filter->beforeAction($this->action());
        });
    }

    public function testSessionHoldsOnlyRequestParameters()
    {
        $this->request(['response_type' => 'code', 'client_id' => 'app', 'scope' => 'read']);
        (new AuthorizeFilter())->beforeAction($this->action());
        $data = Yii::$app->session->get('ear6kme7or19rnfldtmwsxgzxsrmngqw');
        $this->assertIsArray($data);
        $this->assertSame('code', $data['type']);
        $this->assertSame('app', $data['params']['client_id']);
        $this->assertStringNotContainsString('secret', serialize($data), 'no client secret in the session');
        $this->assertNull($data['params']['redirect_uri'], 'the raw request is stored, not the defaults');
    }

    public function testStoredRequestIsRevalidated()
    {
        $this->request(['response_type' => 'code', 'client_id' => 'app', 'scope' => 'write']);
        (new AuthorizeFilter())->beforeAction($this->action());
        Yii::$app->db->createCommand()->update('{{%oauth2_client}}', ['scope' => 'read'], ['client_id' => 'app'])->execute();

        $this->login();
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $this->request([]);
        $filter = new AuthorizeFilter();
        $filter->beforeAction($this->action());
        $filter->finishAuthorization();
        $this->assertStringStartsWith('https://app.example.com/cb?error=invalid_scope', Yii::$app->response->headers->get('Location'));
    }

    public function testGrantTypeOfClientIsCheckedAtAuthorizationEndpoint()
    {
        $this->createClient('cc-only', 's', 'https://cc.example.com/cb', 'client_credentials');
        $this->request(['response_type' => 'code', 'client_id' => 'cc-only']);
        $this->assertFalse((new AuthorizeFilter())->beforeAction($this->action()));
        $this->assertStringStartsWith('https://cc.example.com/cb?error=unauthorized_client', Yii::$app->response->headers->get('Location'));
    }

    public function testLoopbackAndCustomSchemeRedirectUrisAreAccepted()
    {
        $this->createClient('native', '', "http://127.0.0.1:8080/cb com.example.app:/cb");
        foreach (['http://127.0.0.1:8080/cb', 'com.example.app:/cb'] as $uri) {
            $model = $this->model(Authorization::class, [
                'response_type' => 'code', 'client_id' => 'native', 'redirect_uri' => $uri,
                'code_challenge' => str_repeat('a', 43), 'code_challenge_method' => 'S256',
            ]);
            $this->assertTrue($model->validate(), $uri);
        }
    }

    public function testArrayScopeIsInvalidRequest()
    {
        $model = $this->model(Authorization::class, ['response_type' => 'code', 'client_id' => 'app', 'scope' => [['read']]]);
        $this->assertOAuthError(Exception::INVALID_REQUEST, function () use ($model) {
            $model->validate();
        });
    }

    public function testIssuerIsAddedToResponse()
    {
        $this->login();
        $model = $this->model(Authorization::class, ['response_type' => 'code', 'client_id' => 'app']);
        $model->issuer = 'https://server.example.com';
        $this->assertTrue($model->validate());
        parse_str($model->getResponseData()['query'], $query);
        $this->assertSame('https://server.example.com', $query['iss']);
    }
}
