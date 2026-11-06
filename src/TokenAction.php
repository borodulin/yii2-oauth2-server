<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use Yii;
use yii\base\Action;
use yii\web\Response;

/**
 * @author Andrey Borodulin
 */
class TokenAction extends Action
{
    /** Format of response
     * @var string
     */
    public $format = Response::FORMAT_JSON;

    /**
     * Whether the token endpoint accepts GET requests and parameters in the query string.
     * RFC 6749 requires POST: client secrets, codes and passwords in URLs end up in server and proxy logs.
     * @var bool
     */
    public $allowGet = false;

    /**
     * Request parameters that must never be accepted from the query string.
     * @var string[]
     */
    public $bodyOnlyParams = ['client_secret', 'code', 'code_verifier', 'refresh_token', 'password', 'assertion'];

    public $grantTypes = [
        'authorization_code' => 'conquer\oauth2\granttypes\Authorization',
        'refresh_token' => 'conquer\oauth2\granttypes\RefreshToken',
        'client_credentials' => 'conquer\oauth2\granttypes\ClientCredentials',
//         'password' => 'conquer\oauth2\granttypes\UserCredentials',
//         'urn:ietf:params:oauth:grant-type:jwt-bearer' => 'conquer\oauth2\granttypes\JwtBearer',
    ];

    public function init()
    {
        Yii::$app->response->format = $this->format;
        // token responses must not be cached (RFC 6749, 5.1)
        Yii::$app->response->headers->set('Cache-Control', 'no-store');
        Yii::$app->response->headers->set('Pragma', 'no-cache');
        $this->controller->enableCsrfValidation = false;
    }

    public function run()
    {
        if (!$this->allowGet) {
            $request = Yii::$app->request;
            if (!$request->getIsPost()) {
                throw new Exception(Yii::t('conquer/oauth2', 'The token endpoint accepts only POST requests.'));
            }
            if (array_intersect($this->bodyOnlyParams, array_keys($request->getQueryParams()))) {
                throw new Exception(Yii::t('conquer/oauth2', 'Credentials must be sent in the request body, not in the URL.'));
            }
        }
        if (!($grantType = BaseModel::getRequestValue('grant_type')) || !is_string($grantType)) {
            throw new Exception(Yii::t('conquer/oauth2', 'The grant type was not specified in the request.'));
        }
        if (isset($this->grantTypes[$grantType])) {
            $grantModel = Yii::createObject($this->grantTypes[$grantType]);
        } else {
            throw new Exception(Yii::t('conquer/oauth2', 'An unsupported grant type was requested.'), Exception::UNSUPPORTED_GRANT_TYPE);
        }

        $grantModel->validate();

        Yii::$app->response->data = $grantModel->getResponseData();
    }
}
