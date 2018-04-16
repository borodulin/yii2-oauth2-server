<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\console;

use yii\console\Controller;
use conquer\oauth2\models\AuthorizationCode;
use conquer\oauth2\models\RefreshToken;
use conquer\oauth2\models\AccessToken;

/**
 * Class Oauth2Controller
 * @package conquer\oauth2\console
 * @author Andrey Borodulin
 */
class Oauth2Controller extends Controller
{
    public function actionIndex()
    {
        echo "Use clear action to delete old tokens";
    }

    public function actionClear()
    {
        AuthorizationCode::deleteAll(['<', 'expires', time()]);
        RefreshToken::deleteAll(['<', 'expires', time()]);
        AccessToken::deleteAll(['<', 'expires', time()]);
    }
}
