<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

use conquer\oauth2\Exception;
use conquer\oauth2\OAuth2;
use conquer\oauth2\services\AuthorizationCodeService;
use conquer\oauth2\services\ClientService;

/**
 * @link https://tools.ietf.org/html/rfc6749#section-4.1.3
 * @author Andrey Borodulin
 */
class AuthorizationGrant implements GrantInterface
{
    /**
     * @var ClientService
     */
    private $clientService;
//
//    /**
//     * The authorization code received from the authorization server.
//     * @var string
//     */
//    public $code;
//
//    /**
//     * REQUIRED, if the "redirect_uri" parameter was included in the
//     * authorization request as described in Section 4.1.1, and their
//     * values MUST be identical.
//     * @link https://tools.ietf.org/html/rfc6749#section-4.1.1
//     * @var string
//     */
//    public $redirect_uri;
//
//    /**
//     * Access Token Scope
//     * @link https://tools.ietf.org/html/rfc6749#section-3.3
//     * @var string
//     */
//    public $scope;
//
    /**
     * @var AuthorizationCodeService
     */
    private $codeService;


    /**
     * AuthorizationGrant constructor.
     * @param ClientService $clientService
     * @param AuthorizationCodeService $codeService
     */
    public function __construct(ClientService $clientService, AuthorizationCodeService $codeService)
    {
        $this->clientService = $clientService;
        $this->codeService = $codeService;
        $this->oauth2 = OAuth2::instance();
    }

    /**
     * @return array
     * @throws Exception
     * @throws \Exception
     * @throws \Throwable
     * @throws \conquer\oauth2\RedirectException
     * @throws \yii\base\Exception
     * @throws \yii\db\StaleObjectException
     */
    public function getResponseData()
    {
        $this->codeService->validateRedirectUri();
        $this->clientService->validateRedirectUri();

        $authCode = $this->codeService->authorizationCode;

        $accessToken = $authCode->createAccessToken();

        $refreshToken = $authCode->createRefreshToken();

        /**
         * The client MUST NOT use the authorization code more than once.
         * @link https://tools.ietf.org/html/rfc6749#section-4.1.2
         */
        $authCode->delete();

        return [
            'access_token' => $accessToken->access_token,
            'expires_in' => OAuth2::instance()->accessTokenLifetime,
            'token_type' => OAuth2::instance()->tokenType,
            'scope' => $authCode->scope,
            'refresh_token' => $refreshToken->refresh_token,
        ];
    }
}
