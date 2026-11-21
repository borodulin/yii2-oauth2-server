<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\console;

use yii\console\Controller;
use yii\console\ExitCode;
use conquer\oauth2\models\AuthorizationCode;
use conquer\oauth2\models\RefreshToken;
use conquer\oauth2\models\AccessToken;

/**
 * @author Andrey Borodulin
 */
class Oauth2Controller extends Controller
{
    /**
     * Deletes expired authorization codes and tokens. Run it periodically, e.g. from cron.
     * @return int
     */
    public function actionIndex()
    {
        return $this->actionClear();
    }

    /**
     * Deletes expired authorization codes and tokens. Run it periodically, e.g. from cron.
     * @return int
     */
    public function actionClear()
    {
        $now = time();
        $count = AuthorizationCode::deleteAll(['<', 'expires', $now])
            + RefreshToken::deleteAll(['<', 'expires', $now])
            + AccessToken::deleteAll(['<', 'expires', $now]);
        $this->stdout("Deleted $count expired codes and tokens.\n");
        return ExitCode::OK;
    }
}
