<?php

namespace tests\unit\flow;

use conquer\oauth2\BaseModel;
use conquer\oauth2\Exception;
use conquer\oauth2\granttypes\Authorization;
use conquer\oauth2\granttypes\ClientCredentials;
use conquer\oauth2\granttypes\JwtBearer;
use conquer\oauth2\granttypes\RefreshToken;
use conquer\oauth2\granttypes\UserCredentials;
use conquer\oauth2\JwtValidator;
use conquer\oauth2\models\Client;
use conquer\oauth2\models\AccessToken;
use Firebase\JWT\JWT;
use tests\OAuthTestCase;
use Yii;
use yii\base\InvalidConfigException;
use yii\caching\ArrayCache;
use yii\caching\DummyCache;

/**
 * JWT bearer grant and JWT client authentication (RFC 7523).
 */
class JwtTest extends OAuthTestCase
{
    const AUDIENCE = 'https://server.example.com/oauth2/token';

    /**
     * @var array<string, array{private: string, public: string}>
     */
    private static $keys = [];

    protected function _before()
    {
        if (!class_exists(JWT::class)) {
            $this->markTestSkipped('firebase/php-jwt is not installed');
        }
        parent::_before();
        Yii::$container->set(JwtValidator::class, ['audience' => self::AUDIENCE]);
        Yii::$app->set('cache', ArrayCache::class);
        $this->createClient('jwt', 'jwt-secret', 'https://jwt.example.com/cb', JwtBearer::GRANT_TYPE . ' client_credentials refresh_token authorization_code');
        $this->setPublicKey('jwt', self::key('rsa')['public']);
        $this->setPublicKey('app', self::key('rsa')['public']);
    }

    protected function _after()
    {
        Yii::$container->clear(JwtValidator::class);
        parent::_after();
    }

    /**
     * @param string $type "rsa", "rsa2" or "ec"
     * @return array{private: string, public: string}
     */
    private static function key($type)
    {
        if (!isset(self::$keys[$type])) {
            $options = $type === 'ec'
                ? ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']
                : ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048];
            $key = openssl_pkey_new($options);
            openssl_pkey_export($key, $private);
            self::$keys[$type] = ['private' => $private, 'public' => openssl_pkey_get_details($key)['key']];
        }
        return self::$keys[$type];
    }

    private function setPublicKey($clientId, $publicKey)
    {
        Yii::$app->db->createCommand()->update('{{%oauth2_client}}', ['public_key' => $publicKey], ['client_id' => $clientId])->execute();
    }

    private function jwt(array $claims = [], $keyType = 'rsa', $alg = 'RS256')
    {
        $claims = array_merge([
            'iss' => 'jwt',
            'sub' => '42',
            'aud' => self::AUDIENCE,
            'exp' => time() + 300,
            'iat' => time(),
            'jti' => Yii::$app->security->generateRandomString(16),
        ], $claims);
        return JWT::encode(array_filter($claims, function ($v) {
            return $v !== null;
        }), self::key($keyType)['private'], $alg);
    }

    private function grant(array $params)
    {
        return $this->model(JwtBearer::class, array_merge(['grant_type' => JwtBearer::GRANT_TYPE], $params));
    }

    private function assertion(array $claims = [])
    {
        return [
            'client_assertion_type' => BaseModel::CLIENT_ASSERTION_TYPE_JWT,
            'client_assertion' => $this->jwt(array_merge(['iss' => 'jwt', 'sub' => 'jwt'], $claims)),
        ];
    }

    // JWT bearer grant

    public function testGrantIssuesAccessTokenForSubject()
    {
        $model = $this->grant(['assertion' => $this->jwt(), 'scope' => 'read']);
        $this->assertTrue($model->validate());
        $data = $model->getResponseData();
        $this->assertSame('read', $data['scope']);
        $this->assertArrayNotHasKey('refresh_token', $data);
        $token = AccessToken::findOne($data['access_token']);
        $this->assertNotNull($token);
        $this->assertSame('jwt', $token->client_id);
        $this->assertEquals(42, $token->user_id);
    }

    public function testGrantAcceptsEcKeyAndAudienceList()
    {
        $this->setPublicKey('jwt', self::key('ec')['public']);
        $model = $this->grant(['assertion' => $this->jwt(['aud' => ['https://other', self::AUDIENCE]], 'ec', 'ES256')]);
        $this->assertTrue($model->validate());
    }

    public function testGrantWithClientIdOfAnotherClientIsRejected()
    {
        $model = $this->grant(['assertion' => $this->jwt(), 'client_id' => 'app']);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testGrantMustBeExplicitlyAllowedForClient()
    {
        // "app" has a public key and an empty grant_type (all grants), but jwt-bearer is not listed
        $model = $this->grant(['assertion' => $this->jwt(['iss' => 'app'])]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testGrantRequiresPublicKey()
    {
        $this->setPublicKey('jwt', null);
        $model = $this->grant(['assertion' => $this->jwt()]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1?: string, 2?: string}>
     */
    public static function invalidAssertionProvider()
    {
        return [
            'signed with another key' => [[], 'rsa2'],
            'expired' => [['exp' => time() - 120]],
            'exp too far in the future' => [['exp' => time() + 86400]],
            'without exp' => [['exp' => null]],
            'not yet valid' => [['nbf' => time() + 600]],
            'wrong audience' => [['aud' => 'https://evil.example.com/token']],
            'audience with query string' => [['aud' => self::AUDIENCE . '?foo=bar']],
            'without subject' => [['sub' => null]],
            'unknown user' => [['sub' => '0']],
            'unknown client' => [['iss' => 'nobody']],
            'client assertion used as a grant' => [['sub' => 'jwt']],
            'without jti' => [['jti' => null]],
            'array kid' => [[], 'array-kid'],
            'EC algorithm for an RSA key' => [[], 'ec', 'ES256'],
            'HS256 signed with the public key' => [[], 'hs256-public-key'],
            'unsigned' => [[], 'none'],
            'malformed' => [[], 'malformed'],
        ];
    }

    /**
     * @dataProvider invalidAssertionProvider
     * @param array<string, mixed> $claims
     * @param string $keyType
     * @param string $alg
     */
    public function testInvalidAssertionIsRejected(array $claims, $keyType = 'rsa', $alg = 'RS256')
    {
        if ($keyType === 'hs256-public-key') {
            $jwt = JWT::encode(['iss' => 'jwt', 'sub' => '42', 'aud' => self::AUDIENCE, 'exp' => time() + 60], self::key('rsa')['public'], 'HS256');
        } elseif ($keyType === 'none') {
            $parts = explode('.', $this->jwt());
            $jwt = JWT::urlsafeB64Encode('{"alg":"none","typ":"JWT"}') . '.' . $parts[1] . '.';
        } elseif ($keyType === 'array-kid') {
            $parts = explode('.', $this->jwt());
            $jwt = JWT::urlsafeB64Encode('{"alg":"RS256","kid":[1]}') . '.' . $parts[1] . '.' . $parts[2];
        } elseif ($keyType === 'malformed') {
            $jwt = 'not-a-jwt';
        } else {
            $jwt = $this->jwt($claims, $keyType, $alg);
        }
        $model = $this->grant(['assertion' => $jwt]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testReplayedJtiIsRejected()
    {
        $jwt = $this->jwt(['jti' => 'once']);
        $this->assertTrue($this->grant(['assertion' => $jwt])->validate());
        $model = $this->grant(['assertion' => $jwt]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testAudienceMustBeConfigured()
    {
        Yii::$container->set(JwtValidator::class, []);
        $model = $this->grant(['assertion' => $this->jwt()]);
        $this->expectException(InvalidConfigException::class);
        $model->validate();
    }

    public function testReplayCacheMustBeConfigured()
    {
        Yii::$app->set('cache', DummyCache::class);
        $model = $this->grant(['assertion' => $this->jwt()]);
        $this->expectException(InvalidConfigException::class);
        $model->validate();
    }

    public function testReplayProtectionCanBeDisabledExplicitly()
    {
        Yii::$container->set(JwtValidator::class, ['audience' => self::AUDIENCE, 'requireJti' => false, 'replayCache' => null]);
        $jwt = $this->jwt(['jti' => null]);
        $this->assertTrue($this->grant(['assertion' => $jwt])->validate());
        $this->assertTrue($this->grant(['assertion' => $jwt])->validate());
    }

    public function testGrantWithValidClientSecret()
    {
        $this->assertTrue($this->grant(['assertion' => $this->jwt(), 'client_id' => 'jwt', 'client_secret' => 'jwt-secret'])->validate());
    }

    public function testGrantWithWrongClientSecret()
    {
        $model = $this->grant(['assertion' => $this->jwt(), 'client_id' => 'jwt', 'client_secret' => 'wrong']);
        $this->assertOAuthError(Exception::INVALID_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testGrantWithClientAssertion()
    {
        $this->assertTrue($this->grant(array_merge(['assertion' => $this->jwt()], $this->assertion()))->validate());
    }

    // JWT client authentication

    public function testClientCredentialsWithClientAssertion()
    {
        $model = $this->model(ClientCredentials::class, array_merge(['grant_type' => 'client_credentials'], $this->assertion()));
        $this->assertTrue($model->validate());
        $this->assertSame('jwt', $model->client_id, 'client_id is taken from the assertion');
    }

    public function testRefreshTokenWithClientAssertion()
    {
        $token = $this->createRefreshToken('jwt');
        $model = $this->model(RefreshToken::class, array_merge([
            'grant_type' => 'refresh_token',
            'client_id' => 'jwt',
            'refresh_token' => $token->refresh_token,
        ], $this->assertion()));
        $this->assertTrue($model->validate());
    }

    public function testAuthorizationCodeWithClientAssertion()
    {
        $code = $this->createCode('jwt', ['redirect_uri' => '']);
        $model = $this->model(Authorization::class, array_merge([
            'grant_type' => 'authorization_code',
            'code' => $code->authorization_code,
        ], $this->assertion()));
        $this->assertTrue($model->validate());
    }

    public function testAuthorizationCodeWithInvalidClientAssertion()
    {
        $code = $this->createCode('jwt', ['redirect_uri' => '']);
        $model = $this->model(Authorization::class, array_merge([
            'grant_type' => 'authorization_code',
            'code' => $code->authorization_code,
        ], $this->assertion(['exp' => time() - 120])));
        $this->assertOAuthError(Exception::INVALID_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testClientAssertionSubjectMustBeTheClient()
    {
        $model = $this->model(ClientCredentials::class, array_merge(
            ['grant_type' => 'client_credentials', 'client_id' => 'jwt'],
            $this->assertion(['sub' => 'app'])
        ));
        $this->assertOAuthError(Exception::INVALID_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testClientAssertionOfAnotherClientIsRejected()
    {
        // signed with the key of "jwt", but claims to be "other" which has another key
        $this->setPublicKey('other', self::key('rsa2')['public']);
        $model = $this->model(ClientCredentials::class, array_merge(
            ['grant_type' => 'client_credentials'],
            $this->assertion(['iss' => 'other', 'sub' => 'other'])
        ));
        $this->assertOAuthError(Exception::INVALID_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testClientAssertionAndSecretTogetherAreRejected()
    {
        $model = $this->model(ClientCredentials::class, array_merge(
            ['grant_type' => 'client_credentials', 'client_id' => 'jwt', 'client_secret' => 'jwt-secret'],
            $this->assertion()
        ));
        $this->assertOAuthError(Exception::INVALID_REQUEST, function () use ($model) {
            $model->validate();
        });
    }

    public function testUnsupportedClientAssertionTypeIsRejected()
    {
        $model = $this->model(ClientCredentials::class, [
            'grant_type' => 'client_credentials',
            'client_id' => 'jwt',
            'client_assertion_type' => 'urn:example:saml',
            'client_assertion' => 'whatever',
        ]);
        $this->assertOAuthError(Exception::INVALID_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testClientSecretIsStillRequiredWithoutAssertion()
    {
        $model = $this->model(ClientCredentials::class, ['grant_type' => 'client_credentials', 'client_id' => 'jwt']);
        $this->assertOAuthError(Exception::INVALID_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testReplayedClientAssertionIsRejected()
    {
        $assertion = $this->assertion();
        $params = array_merge(['grant_type' => 'client_credentials'], $assertion);
        $this->assertTrue($this->model(ClientCredentials::class, $params)->validate());
        $model = $this->model(ClientCredentials::class, $params);
        $this->assertOAuthError(Exception::INVALID_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testPasswordGrantWithClientAssertion()
    {
        $model = $this->model(UserCredentials::class, array_merge(
            ['grant_type' => 'password', 'username' => 'u', 'password' => 'p'],
            $this->assertion()
        ));
        // the client is authenticated, then the grant type is checked: "jwt" may not use the password grant
        $this->assertOAuthError(Exception::UNAUTHORIZED_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testClientAssertionTypeWithoutAssertion()
    {
        $model = $this->model(ClientCredentials::class, [
            'grant_type' => 'client_credentials',
            'client_id' => 'jwt',
            'client_assertion_type' => BaseModel::CLIENT_ASSERTION_TYPE_JWT,
        ]);
        $this->assertOAuthError(Exception::INVALID_REQUEST, function () use ($model) {
            $model->validate();
        });
    }

    public function testClientWorksWithoutPublicKeyColumn()
    {
        // schema before m261122_120000_oauth_jwt (SQLite cannot drop columns)
        Yii::$app->db->createCommand()->dropTable('{{%oauth2_client}}')->execute();
        Yii::$app->db->createCommand()->createTable('{{%oauth2_client}}', [
            'client_id' => 'string(80) NOT NULL PRIMARY KEY',
            'client_secret' => 'string(80) NOT NULL',
            'redirect_uri' => 'text NOT NULL',
            'grant_type' => 'text',
            'scope' => 'text',
            'created_at' => 'integer',
            'updated_at' => 'integer',
            'created_by' => 'integer',
            'updated_by' => 'integer',
        ])->execute();
        Yii::$app->db->schema->refresh();
        $client = new Client();
        $client->load(['client_id' => 'x', 'client_secret' => 's', 'redirect_uri' => 'https://x', 'public_key' => 'k'], '');
        $this->assertTrue($client->validate());
        $this->assertNull($client->getPublicKey());
    }
}
