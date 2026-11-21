<?php

namespace tests\unit\flow;

use conquer\oauth2\Exception;
use conquer\oauth2\granttypes\Authorization;
use conquer\oauth2\models\AccessToken;
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
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'code' => $code->token]);
        $this->assertTrue($model->validate());
        $data = $model->getResponseData();
        $this->assertSame('read', $data['scope'], 'issue #25: response scope must be the granted scope');
        $this->assertNotEmpty($data['access_token']);
        $this->assertNotEmpty($data['refresh_token']);
        $this->assertNotNull(AuthorizationCode::findByToken($code->token)->used, 'code is single-use');
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'code' => $code->token]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
        $this->assertNull(AccessToken::findByToken($data['access_token']), 'a reused code revokes the tokens');
    }

    public function testCodeIssuedToAnotherClientIsRejected()
    {
        $code = $this->createCode('app');
        $model = $this->grant(['client_id' => 'other', 'client_secret' => 'other-secret', 'code' => $code->token]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testClientSecretIsRequired()
    {
        $code = $this->createCode('app');
        $model = $this->grant(['client_id' => 'app', 'code' => $code->token]);
        $this->assertOAuthError(Exception::INVALID_CLIENT, function () use ($model) {
            $model->validate();
        });
        $code = $this->createCode('app');
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'wrong', 'code' => $code->token]);
        $this->assertOAuthError(Exception::INVALID_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testExpiredCodeIsRejected()
    {
        $code = $this->createCode('app', ['expires' => time() - 1]);
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'code' => $code->token]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testRedirectUriMustMatchTheOneUsedForTheCode()
    {
        $code = $this->createCode('app', ['redirect_uri' => 'https://app.example.com/cb']);
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'code' => $code->token]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
        $model = $this->grant([
            'client_id' => 'app', 'client_secret' => 'secret', 'code' => $code->token,
            'redirect_uri' => 'https://app.example.com/cb',
        ]);
        $this->assertTrue($model->validate());
    }

    private static function challenge($verifier)
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    public function testPkceS256AllowsPublicClient()
    {
        $this->createClient('spa', '', 'https://spa.example.com/cb');
        $verifier = str_repeat('v', 50);
        $code = $this->createCode('spa', ['code_challenge' => self::challenge($verifier), 'code_challenge_method' => 'S256']);

        $model = $this->grant(['client_id' => 'spa', 'code' => $code->token, 'code_verifier' => str_repeat('x', 50)]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });

        $model = $this->grant(['client_id' => 'spa', 'code' => $code->token, 'code_verifier' => $verifier]);
        $this->assertTrue($model->validate());
    }

    public function testPkceDoesNotReplaceAuthenticationOfConfidentialClient()
    {
        $verifier = str_repeat('v', 50);
        $code = $this->createCode('app', ['code_challenge' => self::challenge($verifier), 'code_challenge_method' => 'S256']);
        $model = $this->grant(['client_id' => 'app', 'code' => $code->token, 'code_verifier' => $verifier]);
        $this->assertOAuthError(Exception::INVALID_CLIENT, function () use ($model) {
            $model->validate();
        });
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'code' => $code->token, 'code_verifier' => $verifier]);
        $this->assertTrue($model->validate());
    }

    public function testVerifierForCodeWithoutChallengeIsRejected()
    {
        $code = $this->createCode('app');
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'code' => $code->token, 'code_verifier' => str_repeat('v', 50)]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testPublicClientWithoutPkceIsRejected()
    {
        $this->createClient('spa', '', 'https://spa.example.com/cb');
        $code = $this->createCode('spa');
        $model = $this->grant(['client_id' => 'spa', 'code' => $code->token]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testPublicClientMustNotSendSecret()
    {
        $this->createClient('spa', '', 'https://spa.example.com/cb');
        $verifier = str_repeat('v', 50);
        $code = $this->createCode('spa', ['code_challenge' => self::challenge($verifier), 'code_challenge_method' => 'S256']);
        $model = $this->grant(['client_id' => 'spa', 'client_secret' => 'x', 'code' => $code->token, 'code_verifier' => $verifier]);
        $this->assertOAuthError(Exception::INVALID_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testGrantTypeRestrictionIsEnforced()
    {
        $this->createClient('cc-only', 's', 'https://cc.example.com/cb', 'client_credentials');
        $code = $this->createCode('cc-only');
        $model = $this->grant(['client_id' => 'cc-only', 'client_secret' => 's', 'code' => $code->token]);
        $this->assertOAuthError(Exception::UNAUTHORIZED_CLIENT, function () use ($model) {
            $model->validate();
        });
    }
}
