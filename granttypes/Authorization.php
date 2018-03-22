<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

use conquer\oauth2\BaseModel;
use conquer\oauth2\Exception;
use conquer\oauth2\models\AccessToken;
use conquer\oauth2\models\AuthorizationCode;
use conquer\oauth2\models\RefreshToken;

/**
 * @link https://tools.ietf.org/html/rfc6749#section-4.1.3
 * @author Andrey Borodulin
 */
class Authorization extends BaseModel
{
    /**
     * @var AuthorizationCode
     */
    private $_authCode;

    /**
     * Value MUST be set to "authorization_code".
     * @var string
     */
    public $grant_type;

    /**
     * The authorization code received from the authorization server.
     * @var string
     */
    public $code;

    /**
     * REQUIRED, if the "redirect_uri" parameter was included in the
     * authorization request as described in Section 4.1.1, and their
     * values MUST be identical.
     * @link https://tools.ietf.org/html/rfc6749#section-4.1.1
     * @var string
     */
    public $redirect_uri;

    /**
     *
     * @var string
     */
    public $client_id;

    /**
     * Access Token Scope
     * @link https://tools.ietf.org/html/rfc6749#section-3.3
     * @var string
     */
    public $scope;

    public function rules()
    {
        return [
            [['client_id', 'grant_type', 'code'], 'required'],
            [['client_id'], 'string', 'max' => 80],
            [['code'], 'string', 'max' => 40],
            [['redirect_uri'], 'url'],
            [['client_id'], 'validateClientId'],
            [['code'], 'validateCode'],
            [['redirect_uri'], 'validateRedirectUri'],
        ];
    }

    /**
     * @param $attribute
     * @throws Exception
     * @throws \conquer\oauth2\RedirectException
     */
    public function validateRedirectUri($attribute)
    {
        $authCode = $this->getAuthCode();

        if ($authCode->redirect_uri && (strcasecmp($this->$attribute, $authCode->redirect_uri) !== 0)) {
            $this->errorServer('The redirect URI provided does not match', Exception::REDIRECT_URI_MISMATCH);
        }
        parent::validateRedirectUri($attribute);
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
        $authCode = $this->getAuthCode();

        $acessToken = AccessToken::createAccessToken([
            'client_id' => $this->client_id,
            'user_id' => $authCode->user_id,
            'expires' => $this->accessTokenLifetime + time(),
            'scope' => $authCode->scope,
        ]);

        $refreshToken = RefreshToken::createRefreshToken([
            'client_id' => $this->client_id,
            'user_id' => $authCode->user_id,
            'expires' => $this->refreshTokenLifetime + time(),
            'scope' => $authCode->scope,
        ]);
        /**
         * The client MUST NOT use the authorization code more than once.
         * @link https://tools.ietf.org/html/rfc6749#section-4.1.2
         */
        $authCode->delete();

        return [
            'access_token' => $acessToken->access_token,
            'expires_in' => $this->accessTokenLifetime,
            'token_type' => $this->tokenType,
            'scope' => $this->scope,
            'refresh_token' => $refreshToken->refresh_token,
        ];
    }

    /**
     * @throws Exception
     * @throws \conquer\oauth2\RedirectException
     */
    public function validateCode()
    {
        $this->getAuthCode();
    }

    /**
     * @return AuthorizationCode
     * @throws Exception
     * @throws \conquer\oauth2\RedirectException
     */
    public function getAuthCode()
    {
        if (is_null($this->_authCode)) {
            if (empty($this->code)) {
                $this->errorRedirect('Authorization code is missing.', Exception::INVALID_REQUEST);
            }
            if (!$this->_authCode = AuthorizationCode::findOne(['authorization_code' => $this->code])) {
                $this->errorRedirect('The authorization code is not found or has been expired.', Exception::INVALID_CLIENT);
            }
        }
        return $this->_authCode;
    }
}
