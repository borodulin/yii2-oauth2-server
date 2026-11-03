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

    private function createSchema()
    {
        $db = Yii::$app->db;
        $db->createCommand()->createTable('{{%oauth2_client}}', [
            'client_id' => 'string(80) NOT NULL PRIMARY KEY',
            'client_secret' => 'string(80) NOT NULL',
            'redirect_uri' => 'text NOT NULL',
            'grant_type' => 'text',
            'scope' => 'text',
            'created_at' => 'integer NOT NULL',
            'updated_at' => 'integer NOT NULL',
            'created_by' => 'integer',
            'updated_by' => 'integer',
        ])->execute();
        foreach (['access_token', 'refresh_token'] as $name) {
            $db->createCommand()->createTable("{{%oauth2_$name}}", [
                $name => 'string(40) NOT NULL PRIMARY KEY',
                'client_id' => 'string(80) NOT NULL',
                'user_id' => 'integer',
                'expires' => 'integer NOT NULL',
                'scope' => 'text',
            ])->execute();
        }
        $db->createCommand()->createTable('{{%oauth2_authorization_code}}', [
            'authorization_code' => 'string(40) NOT NULL PRIMARY KEY',
            'client_id' => 'string(80) NOT NULL',
            'user_id' => 'integer',
            'redirect_uri' => 'text NOT NULL',
            'expires' => 'integer NOT NULL',
            'scope' => 'text',
            'code_challenge' => 'string(128)',
            'code_challenge_method' => 'string(10)',
        ])->execute();
    }

    protected function createClient($id, $secret, $redirectUri, $grantType = null, $scope = 'read write')
    {
        Yii::$app->db->createCommand()->insert('{{%oauth2_client}}', [
            'client_id' => $id,
            'client_secret' => $secret,
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
