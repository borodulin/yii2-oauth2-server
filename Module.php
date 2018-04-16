<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use conquer\oauth2\console\Oauth2Controller;
use yii\base\BootstrapInterface;

/**
 * Class Module
 * @package conquer\oauth2
 * @author Andrey Borodulin
 */
class Module extends \yii\base\Module implements BootstrapInterface
{

    public $behaviors;

    /**
     * @inheritdoc
     */
    public function bootstrap($app)
    {
        if ($app instanceof \yii\console\Application) {
            $app->controllerMap[$this->id] = [
                'class' => Oauth2Controller::class,
            ];
        }
    }

    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        if (!empty($this->behaviors)) {
            return $this->behaviors;
        } else {
            return parent::behaviors();
        }
    }
}
