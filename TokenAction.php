<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use conquer\oauth2\services\GrantTypeService;
use Yii;
use yii\base\Action;
use yii\web\Response;

/**
 * Class TokenAction
 * @package conquer\oauth2
 * @author Andrey Borodulin
 */
class TokenAction extends Action
{
    /** Format of response
     * @var string
     */
    public $format = Response::FORMAT_JSON;

    /**
     * @var GrantTypeService
     */
    private $grantService;

    public function init()
    {
        Yii::$app->response->format = $this->format;
        $this->controller->enableCsrfValidation = false;
        $this->grantService = Yii::createObject(GrantTypeService::class);
    }

    /**
     * @return array
     * @throws \yii\base\InvalidConfigException
     * @throws \yii\web\ServerErrorHttpException
     */
    public function run()
    {
        return $this->grantService->getResponseData();
//        Yii::$app->response->data = $this->grantService->getResponseData()
    }
}
