<?php

namespace tests;

use conquer\oauth2\Exception;
use conquer\oauth2\models\AuthorizationCode;
use conquer\oauth2\models\Client;
use conquer\oauth2\models\RefreshToken;
use Yii;
use yii\db\Connection;

/**
 * Base test case: boots a web application with an in-memory SQLite database.
 */
abstract class OAuthTestCase extends \Codeception\Test\Unit
{
    protected function _before()
    {
        new \yii\web\Application([
            'id' => 'test',
            'basePath' => dirname(__DIR__),
            'vendorPath' => dirname(__DIR__, 2) . '/vendor',
            'components' => [
                'db' => ['class' => Connection::class, 'dsn' => 'sqlite::memory:'],
                'request' => ['cookieValidationKey' => 'test', 'scriptFile' => __FILE__, 'scriptUrl' => '/index.php'],
                'user' => ['identityClass' => TestIdentity::class, 'enableSession' => false],
                'i18n' => ['translations' => ['conquer/oauth2' => [
                    'class' => \yii\i18n\PhpMessageSource::class,
                    'basePath' => dirname(__DIR__, 2) . '/src/messages',
                ]]],
            ],
        ]);
        $this->createSchema();
        $this->createClient('app', 'secret', 'https://app.example.com/cb');
        $this->createClient('other', 'other-secret', 'https://other.example.com/cb');
    }

    protected function _after()
    {
        Yii::$app = null;
    }

    /**
     * Creates the schema with the package migrations.
     */
    protected function createSchema()
    {
        $this->migrate([
            \conquer\oauth2\migrations\m150610_162817_oauth::class,
            \conquer\oauth2\migrations\m261103_120000_oauth_pkce::class,
            \conquer\oauth2\migrations\m261122_120000_oauth_jwt::class,
            \conquer\oauth2\migrations\m261123_120000_oauth_v3::class,
        ]);
    }

    /**
     * @param string[] $migrations
     */
    protected function migrate(array $migrations)
    {
        ob_start();
        try {
            foreach ($migrations as $class) {
                $migration = new $class(['db' => Yii::$app->db, 'compact' => true]);
                if ($migration->up() === false) {
                    throw new \RuntimeException("Migration $class failed");
                }
            }
        } finally {
            ob_end_clean();
        }
    }

    protected function createClient($id, $secret, $redirectUri, $grantType = null, $scope = 'read write')
    {
        Yii::$app->db->createCommand()->insert('{{%oauth2_client}}', [
            'client_id' => $id,
            // secrets are stored as bcrypt hashes; a low cost keeps the tests fast
            'client_secret' => $secret === '' ? '' : Yii::$app->security->generatePasswordHash($secret, 4),
            'redirect_uri' => $redirectUri,
            'grant_type' => $grantType,
            'scope' => $scope,
            'created_at' => time(),
            'updated_at' => time(),
        ])->execute();
        return Client::findOne($id);
    }

    protected function createCode($clientId, array $attributes = [])
    {
        return AuthorizationCode::createAuthorizationCode(array_merge([
            'client_id' => $clientId,
            'user_id' => 42,
            'expires' => time() + 30,
            'scope' => 'read',
            'redirect_uri' => '',
        ], $attributes));
    }

    protected function createRefreshToken($clientId, array $attributes = [])
    {
        return RefreshToken::createRefreshToken(array_merge([
            'client_id' => $clientId,
            'user_id' => 42,
            'expires' => time() + 3600,
            'scope' => 'read write',
        ], $attributes));
    }

    /**
     * Sets request params and creates the model (models read params in init()).
     */
    protected function model($class, array $params)
    {
        Yii::$app->request->setBodyParams($params);
        Yii::$app->request->setQueryParams([]);
        return new $class();
    }

    /**
     * Asserts that validating the model throws an OAuth2 error with the given code.
     */
    protected function assertOAuthError($expectedError, callable $callback)
    {
        try {
            $callback();
        } catch (Exception $e) {
            $this->assertSame($expectedError, $e->getName(), $e->getMessage());
            return;
        }
        $this->fail("Expected OAuth2 error '$expectedError'");
    }
}
