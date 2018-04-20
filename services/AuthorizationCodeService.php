<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\services;

use conquer\oauth2\Exception;
use conquer\oauth2\models\AuthorizationCode;

/**
 * Class AuthorizationCodeService
 * @package conquer\oauth2\services
 * @author Andrey Borodulin
 */
class AuthorizationCodeService
{
    /**
     * @var RequestService
     */
    private $_requestService;

    /**
     * @var AuthorizationCode
     */
    public $authorizationCode;

    /**
     * ClientService constructor.
     * @param RequestService $requestService
     */
    public function __construct(RequestService $requestService)
    {
        $code = $requestService->getParam('code');
        $this->authorizationCode = AuthorizationCode::findOne(['authorization_code' => $code]);
        if (!$this->authorizationCode) {
//            $this->errorRedirect('The authorization code is not found or has been expired.', Exception::INVALID_CLIENT);
        }
        $this->_requestService = $requestService;
    }

    public function validateRedirectUri()
    {
        if ($this->authorizationCode->redirect_uri) {
            $redirectUri = $this->_requestService->getParam('redirect_uri');
            if ((strcasecmp($redirectUri, $this->authorizationCode->redirect_uri) !== 0)) {
                throw new Exception('The redirect URI provided does not match', Exception::REDIRECT_URI_MISMATCH);
            }
        }
    }
}
