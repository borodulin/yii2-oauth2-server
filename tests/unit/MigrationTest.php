<?php

namespace tests\unit;

use conquer\oauth2\granttypes\ClientCredentials;
use conquer\oauth2\migrations\m150610_162817_oauth;
use conquer\oauth2\migrations\m261103_120000_oauth_pkce;
use conquer\oauth2\migrations\m261122_120000_oauth_jwt;
use conquer\oauth2\migrations\m261123_120000_oauth_v3;
use conquer\oauth2\models\AccessToken;
use conquer\oauth2\models\Client;
use tests\OAuthTestCase;
use Yii;

/**
 * Upgrade of an existing 2.x database to 3.0.
 */
class MigrationTest extends OAuthTestCase
{
    protected function createSchema()
    {
        $this->migrate([m150610_162817_oauth::class, m261103_120000_oauth_pkce::class, m261122_120000_oauth_jwt::class]);
    }

    protected function _before()
    {
        parent::_before();
        // rows written by 2.x: plain tokens and secrets
        $db = Yii::$app->db;
        $db->createCommand()->update('{{%oauth2_client}}', ['client_secret' => 'secret'], ['client_id' => 'app'])->execute();
        $db->createCommand()->insert('{{%oauth2_access_token}}', [
            'access_token' => str_repeat('t', 40), 'client_id' => 'app', 'user_id' => 42, 'expires' => time() + 60,
        ])->execute();
        $this->migrate([m261123_120000_oauth_v3::class]);
    }

    public function testExistingTokensAndSecretsStayValid()
    {
        $this->assertNotNull(AccessToken::findByToken(str_repeat('t', 40)));
        $this->assertNull(AccessToken::findOne(str_repeat('t', 40)));

        $client = Client::findOne('app');
        $this->assertTrue(Client::isSecretHash($client->client_secret));
        $model = $this->model(ClientCredentials::class, ['grant_type' => 'client_credentials', 'client_id' => 'app', 'client_secret' => 'secret']);
        $this->assertTrue($model->validate());
    }

    public function testMigrationIsIrreversible()
    {
        ob_start();
        $result = (new m261123_120000_oauth_v3(['db' => Yii::$app->db]))->down();
        ob_end_clean();
        $this->assertFalse($result);
    }
}
