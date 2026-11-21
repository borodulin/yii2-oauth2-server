<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use UnexpectedValueException;
use Yii;
use yii\base\BaseObject;
use yii\base\InvalidConfigException;
use yii\caching\CacheInterface;
use yii\caching\DummyCache;
use yii\di\Instance;

/**
 * Verifies JWTs used as authorization grants and for client authentication (RFC 7523).
 *
 * The JWT must be signed with the private key matching the client's public key, and contain
 * "iss", "sub", "aud" and "exp" claims (RFC 7523, section 3).
 *
 * Requires firebase/php-jwt ^7.0 (PHP 8.0+).
 *
 * [[audience]] must be configured, usually through the DI container:
 *
 * ```php
 * Yii::$container->set(\conquer\oauth2\JwtValidator::class, [
 *     'audience' => 'https://example.com/oauth2/token',
 * ]);
 * ```
 *
 * Replay protection needs a cache shared by all application servers (the "cache" component by default).
 */
class JwtValidator extends BaseObject
{
    /**
     * @var string|string[]|null accepted "aud" values, usually the URL of the token endpoint. Required: it is not
     * derived from the request, because the Host header is controlled by the client.
     */
    public $audience;

    /**
     * @var string[] accepted signature algorithms. Only asymmetric algorithms are supported.
     */
    public $algorithms = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384'];

    /**
     * @var int allowed clock skew in seconds for "exp", "nbf" and "iat"
     */
    public $leeway = 60;

    /**
     * @var int maximum number of seconds "exp" may be in the future, 0 means no limit
     */
    public $maxLifetime = 600;

    /**
     * @var CacheInterface|array<string, mixed>|string|null cache used to reject JWTs with a reused "jti".
     * Null disables replay protection and is allowed only when [[requireJti]] is false.
     * The cache must be shared by all application servers and support atomic add() (e.g. Redis, Memcached, DB).
     */
    public $replayCache = 'cache';

    /**
     * @var bool whether the "jti" claim is required. Without it, a JWT can be used any number of times until it expires.
     */
    public $requireJti = true;

    /**
     * Returns the claims of a JWT without verifying it, null if the JWT is malformed.
     * Use only to find out which key to verify the JWT with.
     * @param mixed $jwt
     * @return array<string, mixed>|null
     */
    public static function peekClaims($jwt)
    {
        if (!is_string($jwt)) {
            return null;
        }
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }
        $claims = json_decode(self::base64UrlDecode($parts[1]), true);
        return is_array($claims) ? $claims : null;
    }

    /**
     * Verifies the signature and claims of a JWT.
     * @param string $jwt
     * @param string $publicKey PEM encoded public key the JWT must be signed with
     * @param string $issuer required value of the "iss" claim
     * @param string|null $subject required value of the "sub" claim, null accepts any non-empty value
     * @return array<string, mixed> claims
     * @throws UnexpectedValueException when the JWT is invalid
     * @throws InvalidConfigException when firebase/php-jwt is not installed
     */
    public function validate($jwt, $publicKey, $issuer, $subject = null)
    {
        if (!class_exists(JWT::class)) {
            throw new InvalidConfigException('JWT support requires firebase/php-jwt: composer require firebase/php-jwt:^7.0');
        }

        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new UnexpectedValueException('Wrong number of segments.');
        }
        $header = json_decode(self::base64UrlDecode($parts[0]), true);
        $alg = is_array($header) && isset($header['alg']) ? $header['alg'] : null;
        if (!is_string($alg) || !in_array($alg, $this->algorithms, true)) {
            throw new UnexpectedValueException('The signature algorithm is not allowed.');
        }
        $this->checkKeyType($publicKey, $alg);

        $leeway = JWT::$leeway;
        JWT::$leeway = $this->leeway;
        try {
            $claims = (array)JWT::decode($jwt, new Key($publicKey, $alg));
        } catch (UnexpectedValueException $e) {
            throw $e;
        } catch (\Throwable $e) {
            // malformed input may also cause TypeError in the library
            throw new UnexpectedValueException($e->getMessage(), 0, $e);
        } finally {
            JWT::$leeway = $leeway;
        }

        if (!isset($claims['iss']) || $claims['iss'] !== $issuer) {
            throw new UnexpectedValueException('The "iss" claim is missing or invalid.');
        }
        if (!isset($claims['sub']) || !is_string($claims['sub']) || $claims['sub'] === ''
            || ($subject !== null && $claims['sub'] !== $subject)
        ) {
            throw new UnexpectedValueException('The "sub" claim is missing or invalid.');
        }
        if (!isset($claims['exp']) || !is_numeric($claims['exp'])) {
            throw new UnexpectedValueException('The "exp" claim is missing.');
        }
        if ($this->maxLifetime > 0 && $claims['exp'] > time() + $this->maxLifetime + $this->leeway) {
            throw new UnexpectedValueException('The "exp" claim is too far in the future.');
        }
        $this->checkAudience(isset($claims['aud']) ? $claims['aud'] : null);
        $this->checkReplay($claims, $issuer);

        return $claims;
    }

    /**
     * @return string[]
     * @throws InvalidConfigException when the audience is not configured
     */
    public function getAudiences()
    {
        if ($this->audience === null || $this->audience === '' || $this->audience === []) {
            throw new InvalidConfigException(__CLASS__ . '::$audience must be configured, usually with the URL of the token endpoint.');
        }
        return (array)$this->audience;
    }

    /**
     * @param mixed $aud
     * @return void
     */
    protected function checkAudience($aud)
    {
        $values = is_array($aud) ? $aud : [$aud];
        foreach ($values as $value) {
            if (is_string($value) && in_array($value, $this->getAudiences(), true)) {
                return;
            }
        }
        throw new UnexpectedValueException('The "aud" claim is missing or invalid.');
    }

    /**
     * @param array<string, mixed> $claims
     * @param string $issuer
     * @return void
     */
    protected function checkReplay($claims, $issuer)
    {
        if (!isset($claims['jti'])) {
            if ($this->requireJti) {
                throw new UnexpectedValueException('The "jti" claim is missing.');
            }
            return;
        }
        if (!is_string($claims['jti']) || $claims['jti'] === '') {
            throw new UnexpectedValueException('The "jti" claim is invalid.');
        }
        $cache = $this->getReplayCache();
        if ($cache === null) {
            return;
        }
        // the JWT is accepted until exp + leeway, keep the jti at least that long
        $ttl = (int)min(max(1, ceil((float)$claims['exp']) - time() + $this->leeway), 86400 * 30);
        if (!$cache->add([__CLASS__, $issuer, $claims['jti']], 1, $ttl)) {
            throw new UnexpectedValueException('The JWT has already been used.');
        }
    }

    /**
     * @return CacheInterface|null
     * @throws InvalidConfigException
     */
    protected function getReplayCache()
    {
        if ($this->replayCache === null) {
            if ($this->requireJti) {
                throw new InvalidConfigException(__CLASS__ . '::$replayCache is required when $requireJti is true.');
            }
            return null;
        }
        /** @var CacheInterface $cache */
        $cache = Instance::ensure($this->replayCache, CacheInterface::class);
        if ($cache instanceof DummyCache) {
            throw new InvalidConfigException(__CLASS__ . '::$replayCache must not be a DummyCache.');
        }
        return $cache;
    }

    /**
     * Checks that the key type matches the algorithm, so that a JWT cannot pick an algorithm for a key.
     * @param string $publicKey
     * @param string $alg
     * @return void
     */
    protected function checkKeyType($publicKey, $alg)
    {
        $key = openssl_pkey_get_public($publicKey);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($details === false) {
            throw new UnexpectedValueException('The public key of the client is invalid.');
        }
        $expected = strncmp($alg, 'ES', 2) === 0 ? OPENSSL_KEYTYPE_EC : OPENSSL_KEYTYPE_RSA;
        if ($details['type'] !== $expected) {
            throw new UnexpectedValueException('The signature algorithm does not match the public key.');
        }
    }

    /**
     * @param string $input
     * @return string
     */
    private static function base64UrlDecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $input .= str_repeat('=', 4 - $remainder);
        }
        return (string)base64_decode(strtr($input, '-_', '+/'), true);
    }
}
