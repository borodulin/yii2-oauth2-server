<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use conquer\oauth2\console\Oauth2Controller;
/**
 * @author Andrey Borodulin
 */
class Module extends \yii\base\Module implements \yii\base\BootstrapInterface
{

    public $behaviors;
    
    /**
     * @inheritdoc
     */
    public function bootstrap($app)
    {
        if ($app instanceof \yii\web\Application) {
            $app->getUrlManager()->addRules([
                    $this->id => $this->id . '/default/index',
                    $this->id . '/<id:\w+>' => $this->id . '/default/view',
                    $this->id . '/<controller:[\w\-]+>/<action:[\w\-]+>' => $this->id . '/<controller>/<action>',
            ], false);
        } elseif ($app instanceof \yii\console\Application) {
            $app->controllerMap[$this->id] = [
                    'class' => Oauth2Controller::className(),
            ];
        }
    }
    
    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        if (!empty($this->behaviors))
            return $this->behaviors;
        else
            return parent::behaviors();
    }
}