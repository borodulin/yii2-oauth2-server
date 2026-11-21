<?php

namespace tests\unit\flow;

use conquer\oauth2\BaseModel;
use conquer\oauth2\Exception;
use conquer\oauth2\granttypes\Authorization;
use conquer\oauth2\granttypes\ClientCredentials;
use conquer\oauth2\granttypes\JwtBearer;
use conquer\oauth2\granttypes\RefreshToken;
use conquer\oauth2\models\AccessToken;
use Firebase\JWT\JWT;
use tests\OAuthTestCase;
use Yii;
use yii\caching\ArrayCache;

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
        parent::_before();
        // the default audience is the URL of the token endpoint
        Yii::$app->request->setHostInfo('https://server.example.com');
        Yii::$app->request->setUrl('/oauth2/token?foo=bar');
        $this->createClient('jwt', 'jwt-secret', 'https://jwt.example.com/cb', JwtBearer::GRANT_TYPE . ' client_credentials refresh_token authorization_code');
        $this->setPublicKey('jwt', self::key('rsa')['public']);
        $this->setPublicKey('app', self::key('rsa')['public']);
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
        $this->assertOAuthError(Exception::UNAUTHORIZED_CLIENT, function () use ($model) {
            $model->validate();
        });
    }

    public function testGrantRequiresPublicKey()
    {
        $this->setPublicKey('jwt', null);
        $model = $this->grant(['assertion' => $this->jwt()]);
        $this->assertOAuthError(Exception::UNAUTHORIZED_CLIENT, function () use ($model) {
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

    public function testReplayedJtiIsRejectedWhenCacheIsConfigured()
    {
        Yii::$app->set('cache', ArrayCache::class);
        $jwt = $this->jwt(['jti' => 'once']);
        $this->assertTrue($this->grant(['assertion' => $jwt])->validate());
        $model = $this->grant(['assertion' => $jwt]);
        $this->assertOAuthError(Exception::INVALID_GRANT, function () use ($model) {
            $model->validate();
        });
    }

    public function testConfiguredAudience()
    {
        Yii::$container->set(\conquer\oauth2\JwtValidator::class, ['audience' => 'https://issuer.example.com']);
        try {
            $this->assertTrue($this->grant(['assertion' => $this->jwt(['aud' => 'https://issuer.example.com'])])->validate());
        } finally {
            Yii::$container->clear(\conquer\oauth2\JwtValidator::class);
        }
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
        // signed with the key of "jwt", but claims to be "other" which has no public key
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
        $this->assertOAuthError(Exception::INVALID_REQUEST, function () use ($model) {
            $model->validate();
        });
    }
}
