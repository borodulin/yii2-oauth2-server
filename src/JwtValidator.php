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
use yii\di\Instance;

/**
 * Verifies JWTs used as authorization grants and for client authentication (RFC 7523).
 *
 * The JWT must be signed with the private key matching the client's public key, and contain
 * "iss", "sub", "aud" and "exp" claims (RFC 7523, section 3).
 *
 * Requires firebase/php-jwt ^7.0 (PHP 8.0+).
 *
 * Can be configured through the DI container:
 *
 * ```php
 * Yii::$container->set(\conquer\oauth2\JwtValidator::class, [
 *     'audience' => 'https://example.com/oauth2/token',
 * ]);
 * ```
 */
class JwtValidator extends BaseObject
{
    /**
     * @var string|string[]|null accepted "aud" values. Null means the absolute URL of the current request
     * without the query string, i.e. the token endpoint.
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
     * A component ID that is not configured in the application disables the check, as does null.
     */
    public $replayCache = 'cache';

    /**
     * @var bool whether the "jti" claim is required
     */
    public $requireJti = false;

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
        } catch (\Exception $e) {
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
     */
    public function getAudiences()
    {
        if ($this->audience === null) {
            return [explode('?', Yii::$app->request->getAbsoluteUrl())[0]];
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
        $ttl = max(1, (int)ceil($claims['exp']) - time() + $this->leeway);
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
        if ($this->replayCache === null
            || (is_string($this->replayCache) && !Yii::$app->has($this->replayCache))
        ) {
            return null;
        }
        return Instance::ensure($this->replayCache, CacheInterface::class);
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
