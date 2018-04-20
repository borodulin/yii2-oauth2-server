<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\services;

use conquer\oauth2\models\AccessToken;
use yii\web\BadRequestHttpException;
use yii\web\UnauthorizedHttpException;

/**
 * Class AccessTokenService
 * @package conquer\oauth2\services
 * @author Andrey Borodulin
 */
class AccessTokenService
{
    /**
     * @var AccessToken
     */
    public $accessToken;

    public function __construct(RequestService $requestService)
    {
        if ($authHeader = $requestService->getHeader('Authorization')) {
            if (preg_match('/^Bearer\\s+(.*?)$/', $authHeader, $matches)) {
                $token = $matches[1];
            } else {
                throw new BadRequestHttpException('Malformed auth header.');
            }
        } else {
            $token = $requestService->getParam('access_token');
        }

        /** @var AccessToken $accessToken */
        $accessToken = AccessToken::findOne(['access_token' => $token]);

        if (!$accessToken) {
            throw new UnauthorizedHttpException('The provided access token is invalid.');
        }
        if ($accessToken->expires < time()) {
            throw new UnauthorizedHttpException('The provided access token has been expired.');
        }
        $this->accessToken = $accessToken;
    }
}
