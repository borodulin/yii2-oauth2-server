<?php

namespace tests\unit\flow;

use conquer\oauth2\Exception;
use conquer\oauth2\granttypes\RefreshToken;
use conquer\oauth2\models\AccessToken;
use conquer\oauth2\models\RefreshToken as RefreshTokenModel;
use tests\OAuthTestCase;
use Yii;

class RefreshTokenGrantTest extends OAuthTestCase
{
    private function grant(array $params)
    {
        return $this->model(RefreshToken::class, array_merge(['grant_type' => 'refresh_token'], $params));
    }

    public function testRefreshRotatesToken()
    {
        $token = $this->createRefreshToken('app');
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'refresh_token' => $token->token]);
        $this->assertTrue($model->validate());
        $data = $model->getResponseData();
        $this->assertNotSame($token->token, $data['refresh_token']);
        $this->assertSame('read write', $data['scope']);
        $this->assertNotNull(RefreshTokenModel::findByToken($token->token)->used, 'the old token is marked used');
        $this->assertNull(RefreshTokenModel::findOne($token->token), 'tokens are stored hashed');
    }

    public function testReusedRefreshTokenRevokesTokens()
    {
        $token = $this->createRefreshToken('app');
        $data = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'refresh_token' => $token->token])->getResponseData();
        $this->assertNotNull(AccessToken::findByToken($data['access_token']));

        // the old token is used again, e.g. by an attacker who stole it
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'refresh_token' => $token->token]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
        $this->assertNull(AccessToken::findByToken($data['access_token']), 'tokens of the family are revoked');
        $this->assertNull(RefreshTokenModel::findByToken($data['refresh_token']));
    }

    public function testNarrowedScopeKeepsGrantedScopeOnRefreshToken()
    {
        $token = $this->createRefreshToken('app', ['scope' => 'read write']);
        $data = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'refresh_token' => $token->token, 'scope' => 'read'])->getResponseData();
        $this->assertSame('read', $data['scope']);
        $this->assertSame('read write', RefreshTokenModel::findByToken($data['refresh_token'])->scope);
    }

    public function testScopeRemovedFromClientIsNotRefreshed()
    {
        $token = $this->createRefreshToken('app', ['scope' => 'read write']);
        Yii::$app->db->createCommand()->update('{{%oauth2_client}}', ['scope' => 'read'], ['client_id' => 'app'])->execute();
        $data = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'refresh_token' => $token->token])->getResponseData();
        $this->assertSame('read', $data['scope']);
    }

    public function testTokenOfAnotherClientIsRejected()
    {
        $token = $this->createRefreshToken('app');
        $model = $this->grant(['client_id' => 'other', 'client_secret' => 'other-secret', 'refresh_token' => $token->token]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testExpiredTokenIsRejected()
    {
        $token = $this->createRefreshToken('app', ['expires' => time() - 1]);
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'refresh_token' => $token->token]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testScopeCanOnlyBeNarrowed()
    {
        $token = $this->createRefreshToken('app', ['scope' => 'read']);
        $model = $this->grant(['client_id' => 'app', 'client_secret' => 'secret', 'refresh_token' => $token->token, 'scope' => 'read write']);
        $this->assertOAuthError(Exception::INVALID_SCOPE, function () use ($model) {
            $model->validate();
        });
    }
}
