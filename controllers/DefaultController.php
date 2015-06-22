<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\controllers;

use yii\web\Controller;

/**
 * @author Andrey Borodulin
 */
class DefaultController extends Controller
{
    public function actionIndex()
    {
        return $this->render('index');
    }
}