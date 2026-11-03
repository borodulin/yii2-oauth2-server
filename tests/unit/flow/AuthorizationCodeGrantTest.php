<?php

namespace tests\unit\flow;

use conquer\oauth2\Exception;
use conquer\oauth2\granttypes\Authorization;
use conquer\oauth2\models\AuthorizationCode;
use tests\OAuthTestCase;

class AuthorizationCodeGrantTest extends OAuthTestCase
{
    private function grant(array $params)
    {
        return $this->model(Authorization::class, array_merge(['grant_type' => 'authorization_code'], $params));
    }

    public function testSuccessfulExchangeReturnsGrantedScope()
    {
        $code = $this->createCode('app', ['scope' => 'read']);
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'code' => $code->authorization_code]);
        $this->assertTrue($model->validate());
        $data = $model->getResponseData();
        $this->assertSame('read', $data['scope'], 'issue #25: response scope must be the granted scope');
        $this->assertNotEmpty($data['access_token']);
        $this->assertNotEmpty($data['refresh_token']);
        $this->assertNull(AuthorizationCode::findOne($code->authorization_code), 'code is single-use');
    }

    public function testCodeIssuedToAnotherClientIsRejected()
    {
        $code = $this->createCode('app');
        $model = $this->grant(['client_id' => 'other', 'client_secret' => 'other-secret', 'code' => $code->authorization_code]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testClientSecretIsRequired()
    {
        $code = $this->createCode('app');
        $model = $this->grant(['client_id' => 'app', 'code' => $code->authorization_code]);
        $this->assertOAuthError(Exception::UNAUTHORIZED_CLIENT, function () use ($model) {
            $model->validate();
        });
        $code = $this->createCode('app');
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'wrong', 'code' => $code->authorization_code]);
        $this->assertOAuthError(Exception::UNAUTHORIZED_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testExpiredCodeIsRejected()
    {
        $code = $this->createCode('app', ['expires' => time() - 1]);
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'code' => $code->authorization_code]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testRedirectUriMustMatchTheOneUsedForTheCode()
    {
        $code = $this->createCode('app', ['redirect_uri' => 'https://app.example.com/cb']);
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'code' => $code->authorization_code]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
        $model = $this->grant([
            'client_id' => 'app', 'client_secret' => 'secret', 'code' => $code->authorization_code,
            'redirect_uri' => 'https://app.example.com/cb',
        ]);
        $this->assertTrue($model->validate());
    }

    public function testPkceS256AllowsPublicClient()
    {
        $verifier = str_repeat('v', 50);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $code = $this->createCode('app', ['code_challenge' => $challenge, 'code_challenge_method' => 'S256']);

        $model = $this->grant(['client_id' => 'app', 'code' => $code->authorization_code, 'code_verifier' => str_repeat('x', 50)]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });

        $model = $this->grant(['client_id' => 'app', 'code' => $code->authorization_code, 'code_verifier' => $verifier]);
        $this->assertTrue($model->validate());
    }

    public function testGrantTypeRestrictionIsEnforced()
    {
        $this->createClient('cc-only', 's', 'https://cc.example.com/cb', 'client_credentials');
        $code = $this->createCode('cc-only');
        $model = $this->grant(['client_id' => 'cc-only', 'client_secret' => 's', 'code' => $code->authorization_code]);
        $this->assertOAuthError(Exception::UNAUTHORIZED_CLIENT, function () use ($model) {
            $model->validate();
        });
    }
}
