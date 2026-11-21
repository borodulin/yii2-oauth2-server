<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\models;

use Yii;

/**
 * Tokens and codes are stored as SHA-256 hashes, so that a database leak does not expose working tokens.
 * The token itself is available in [[token]] only right after it was created.
 */
trait TokenTrait
{
    /**
     * @var string|null the token, set only on a model returned by the create method
     */
    public $token;

    /**
     * @var int percentage of token creations that also delete expired rows; 0 leaves it to `yii oauth2/clear`
     */
    public static $gcProbability = 1;

    /**
     * @return string name of the column that holds the token hash
     */
    abstract public static function tokenAttribute();

    /**
     * @param string $token
     * @return string
     */
    public static function hashToken($token)
    {
        return hash('sha256', (string)$token);
    }

    /**
     * Finds a row by the token sent by a client.
     * @param mixed $token
     * @return static|null
     */
    public static function findByToken($token)
    {
        if (!is_string($token) || $token === '') {
            return null;
        }
        return static::findOne([static::tokenAttribute() => static::hashToken($token)]);
    }

    /**
     * Creates a row with a new random token; [[token]] of the result holds the token.
     * @param array<string, mixed> $attributes
     * @return static|null null when the model does not validate
     * @throws \yii\base\Exception
     */
    protected static function createWithToken(array $attributes)
    {
        if (static::$gcProbability > 0 && mt_rand(1, 100) <= static::$gcProbability) {
            static::deleteAll(['<', 'expires', time()]);
        }
        $token = Yii::$app->security->generateRandomString(40);
        $attributes[static::tokenAttribute()] = static::hashToken($token);
        $model = new static($attributes);
        if (!$model->save()) {
            Yii::error(static::class . ' validation error: ' . \yii\helpers\VarDumper::dumpAsString($model->errors), __METHOD__);
            return null;
        }
        $model->token = $token;
        return $model;
    }

    /**
     * Marks a single-use token as used. Atomic: of concurrent requests with the same token only one succeeds.
     * @return bool false when the token has already been used
     */
    public function markUsed()
    {
        $attribute = static::tokenAttribute();
        return static::updateAll(['used' => time()], [$attribute => $this->$attribute, 'used' => null]) === 1;
    }
}
