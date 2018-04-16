<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use Yii;
use yii\base\Component;
use yii\db\Connection;
use yii\di\Instance;
use yii\web\User;

/**
 * Class OAuth2
 * @package conquer\oauth2
 * @author Andrey Borodulin
 */
class OAuth2 extends Component
{

    /**
     * @var static
     */
    private static $_instance;

    public $db = 'db';

    public $accessTokenTable = '{{%oauth2_access_token}}';

    public $clientTable = '{{%oauth2_client}}';

    public $refreshTokenTable = '{{%oauth2_refresh_token}}';

    public $authorizationCodeTable = '{{%oauth2_authorization_code}}';


    /**
     * @link https://tools.ietf.org/html/rfc6749#section-7.1
     * @var string
     */
    public $tokenType = 'bearer';

    /**
     * Authorization Code lifetime
     * 30 seconds by default
     * @var integer
     */
    public $authCodeLifetime = 30;

    /**
     * Access Token lifetime
     * 1 hour by default
     * @var integer
     */
    public $accessTokenLifetime = 3600;

    /**
     * Refresh Token lifetime
     * 2 weeks by default
     * @var integer
     */
    public $refreshTokenLifetime = 1209600;

    /**
     * @var bool
     */
    public $clearOldTokens = true;

    /**
     * @var string the class name of the [[identity]] object.
     */
    public $identityClass;

    /**
     * @throws \yii\base\InvalidConfigException
     */
    public function init()
    {
        $this->db = Instance::ensure($this->db, Connection::class);
        if ($this->identityClass === null) {
            /** @var User $user */
            if ($user = Yii::$app->get('user', false)) {
                $this->identityClass = $user->identityClass;
            }
        }
    }

    /**
     * @return OAuth2
     * @throws \yii\base\InvalidConfigException
     */
    public static function instance()
    {
        if (self::$_instance === null) {
            self::$_instance = Yii::$app->get('oauth2', false);
            if (!self::$_instance instanceof OAuth2) {
                self::$_instance = Yii::createObject(get_called_class());
            }
        }
        return self::$_instance;
    }
}