<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\services;

use conquer\oauth2\responsetypes\AuthorizationResponse;
use conquer\oauth2\responsetypes\ImplicitResponse;
use conquer\oauth2\responsetypes\ResponseTypeInterface;
use Yii;
use yii\web\ServerErrorHttpException;

/**
 * Class ResponseTypeService
 * @package conquer\oauth2\services
 * @author Andrey Borodulin
 */
class ResponseTypeService
{
    const AUTHORIZATION_CODE = 'code';
    const IMPLICIT_TOKEN = 'token';

    public static $responseTypeMap = [
        self::AUTHORIZATION_CODE => AuthorizationResponse::class,
        self::IMPLICIT_TOKEN => ImplicitResponse::class,
    ];

    /**
     * @var RequestService
     */
    private $_requestService;

    /**
     * ResponseTypeService constructor.
     * @param RequestService $requestService
     */
    public function __construct(RequestService $requestService)
    {
        $this->_requestService = $requestService;
    }

    public function validate()
    {
    }

    /**
     * @return array
     * @throws ServerErrorHttpException
     * @throws \yii\base\InvalidConfigException
     */
    public function getResponseData()
    {
        $responseType = $this->_requestService->getParam('response_type');
        if (isset(self::$responseTypeMap[$responseType])) {
            $className = self::$responseTypeMap[$responseType];
            /** @var ResponseTypeInterface $response */
            $response = Yii::createObject($className);
            return $response->getResponseData();
        }
        throw new ServerErrorHttpException('Invalid response type');
    }

    public function getResponseRedirectUri()
    {
//        $parts = $this->getResponseData();
//
//        $redirectUri = http_build_url($responseType->redirect_uri, $parts, HTTP_URL_JOIN_QUERY | HTTP_URL_STRIP_FRAGMENT);
//
//        if (isset($parts['fragment'])) {
//            $redirectUri .= '#' . $parts['fragment'];
//        }
    }
}
