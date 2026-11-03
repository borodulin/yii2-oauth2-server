<?php

namespace tests\unit\flow;

use conquer\oauth2\Exception;
use conquer\oauth2\granttypes\RefreshToken;
use tests\OAuthTestCase;

class RefreshTokenGrantTest extends OAuthTestCase
{
    private function grant(array $params)
    {
        return $this->model(RefreshToken::class, array_merge(['grant_type' => 'refresh_token'], $params));
    }

    public function testRefreshRotatesToken()
    {
        $token = $this->createRefreshToken('app');
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'refresh_token' => $token->refresh_token]);
        $this->assertTrue($model->validate());
        $data = $model->getResponseData();
        $this->assertNotSame($token->refresh_token, $data['refresh_token']);
        $this->assertSame('read write', $data['scope']);
        $this->assertNull(\conquer\oauth2\models\RefreshToken::findOne($token->refresh_token));
    }

    public function testTokenOfAnotherClientIsRejected()
    {
        $token = $this->createRefreshToken('app');
        $model = $this->grant(['client_id' => 'other', 'client_secret' => 'other-secret', 'refresh_token' => $token->refresh_token]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testExpiredTokenIsRejected()
    {
        $token = $this->createRefreshToken('app', ['expires' => time() - 1]);
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'refresh_token' => $token->refresh_token]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testScopeCanOnlyBeNarrowed()
    {
        $token = $this->createRefreshToken('app', ['scope' => 'read']);
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'refresh_token' => $token->refresh_token, 'scope' => 'read write']);
        $this->assertOAuthError(Exception::INVALID_SCOPE, function () use ($model) {
            $model->validate();
        });
    }
}
