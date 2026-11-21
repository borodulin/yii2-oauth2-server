<?php

namespace tests\unit\flow;

use conquer\oauth2\Exception;
use conquer\oauth2\responsetypes\Authorization;
use tests\OAuthTestCase;

class AuthorizationRequestTest extends OAuthTestCase
{
    public function testExactRedirectUriIsAccepted()
    {
        $model = $this->model(Authorization::class, [
            'response_type' => 'code', 'client_id' => 'app', 'redirect_uri' => 'https://app.example.com/cb',
        ]);
        $this->assertTrue($model->validate());
    }

    public function testRedirectUriPrefixAttackIsRejected()
    {
        foreach (['https://app.example.com/cb.evil.net', 'https://app.example.com/cb/../../evil', 'HTTPS://APP.EXAMPLE.COM/CB'] as $uri) {
            $model = $this->model(Authorization::class, [
                'response_type' => 'code', 'client_id' => 'app', 'redirect_uri' => $uri,
            ]);
            $this->assertOAuthError(Exception::INVALID_REQUEST, function () use ($model) {
                $model->validate();
            });
        }
    }

    public function testRegisteredRedirectUriIsUsedWhenOmitted()
    {
        $model = $this->model(Authorization::class, ['response_type' => 'code', 'client_id' => 'app']);
        $this->assertTrue($model->validate());
        $this->assertSame('https://app.example.com/cb', $model->redirect_uri);
    }

    public function testRedirectUriRequiredWhenSeveralRegistered()
    {
        $this->createClient('multi', 's', "https://a.example.com/cb\nhttps://b.example.com/cb");
        $model = $this->model(Authorization::class, ['response_type' => 'code', 'client_id' => 'multi']);
        $this->assertOAuthError(Exception::INVALID_REQUEST, function () use ($model) {
            $model->validate();
        });

        $model = $this->model(Authorization::class, [
            'response_type' => 'code', 'client_id' => 'multi', 'redirect_uri' => 'https://b.example.com/cb',
        ]);
        $this->assertTrue($model->validate());
    }

    public function testCodeStoresPkceChallenge()
    {
        \Yii::$app->user->setIdentity(new \tests\TestIdentity(['id' => 7]));
        $model = $this->model(Authorization::class, [
            'response_type' => 'code', 'client_id' => 'app',
            'code_challenge' => str_repeat('a', 43), 'code_challenge_method' => 'S256',
        ]);
        $this->assertTrue($model->validate());
        parse_str($model->getResponseData()['query'], $query);
        $code = \conquer\oauth2\models\AuthorizationCode::findOne($query['code']);
        $this->assertSame(str_repeat('a', 43), $code->code_challenge);
        $this->assertSame('S256', $code->code_challenge_method);
        $this->assertSame('', $code->redirect_uri, 'redirect_uri taken from client is not bound to the code');
    }

    public function testPlainPkceIsRejectedByDefault()
    {
        foreach ([['code_challenge' => str_repeat('a', 43)], ['code_challenge' => str_repeat('a', 43), 'code_challenge_method' => 'plain']] as $params) {
            $model = $this->model(Authorization::class, array_merge(['response_type' => 'code', 'client_id' => 'app'], $params));
            $this->assertOAuthError(Exception::INVALID_REQUEST, function () use ($model) {
                $model->validate();
            });
        }
    }

    public function testMalformedCodeChallengeIsRejected()
    {
        $model = $this->model(Authorization::class, [
            'response_type' => 'code', 'client_id' => 'app', 'code_challenge' => str_repeat('a', 42) . '=', 'code_challenge_method' => 'S256',
        ]);
        $this->assertOAuthError(Exception::INVALID_REQUEST, function () use ($model) {
            $model->validate();
        });
    }

    public function testPublicClientMustSendCodeChallenge()
    {
        $this->createClient('spa', '', 'https://spa.example.com/cb');
        $model = $this->model(Authorization::class, ['response_type' => 'code', 'client_id' => 'spa']);
        $this->assertOAuthError(Exception::INVALID_REQUEST, function () use ($model) {
            $model->validate();
        });
    }
}
