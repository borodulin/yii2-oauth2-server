<?php
/**
 * Created by PhpStorm.
 * User: borodulin
 * Date: 26.03.18
 * Time: 12:41
 */

namespace conquer\oauth2;

use yii\base\Component;
use yii\db\Connection;
use yii\di\Instance;

class OAuth2 extends Component
{

    public $db = 'db';

    public $accessTokenTable = '{{%oauth2_access_token}}';

    public $clientTable = '{{%oauth2_client}}';

    public $refreshTokenTable = '{{%oauth2_refresh_token}}';

    public $authorizationCodeTable = '{{%oauth2_authorization_code}}';

    /**
     * @throws \yii\base\InvalidConfigException
     */
    public function init()
    {
        $this->db = Instance::ensure($this->db, Connection::class);
    }
}