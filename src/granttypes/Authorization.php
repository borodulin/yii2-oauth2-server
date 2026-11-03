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
use Yii;

/**
 * Authorization code grant.
 *
 * The client authenticates either with its client_secret (confidential clients)
 * or with a PKCE code_verifier when the authorization request contained a code_challenge
 * (public clients, RFC 7636).
 *
 * @link https://tools.ietf.org/html/rfc6749#section-4.1.3
 * @link https://tools.ietf.org/html/rfc7636
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
     * REQUIRED, if the "redirect_uri" parameter was included in the authorization request,
     * and their values MUST be identical.
     * @var string
     */
    public $redirect_uri;

    /**
     * @var string
     */
    public $client_id;

    /**
     * Required unless the code was issued with a PKCE code_challenge.
     * @var string
     */
    public $client_secret;

    /**
     * PKCE code verifier.
     * @var string
     */
    public $code_verifier;

    public function rules()
    {
        return [
            [['client_id', 'grant_type', 'code'], 'required'],
            ['grant_type', 'required', 'requiredValue' => 'authorization_code'],
            [['client_id', 'client_secret'], 'string', 'max' => 80],
            [['code'], 'string', 'max' => 40],
            [['code_verifier'], 'string', 'min' => 43, 'max' => 128],
            [['redirect_uri'], 'string'],
            [['client_id'], 'validateClientId'],
            [['code'], 'validateCode', 'skipOnEmpty' => false],
        ];
    }

    /**
     * Validates the code, its owner, lifetime, redirect URI and client authentication.
     */
    public function validateCode()
    {
        $authCode = $this->getAuthCode();
        $this->checkGrantType('authorization_code');

        if ($authCode->client_id !== $this->client_id) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The authorization code was issued to another client.'), Exception::INVALID_GRANT);
        }
        if ($authCode->expires < time()) {
            $authCode->delete();
            $this->errorServer(Yii::t('conquer/oauth2', 'The authorization code is not found or has been expired.'), Exception::INVALID_GRANT);
        }
        if (!empty($authCode->redirect_uri) && $this->redirect_uri !== $authCode->redirect_uri) {
            $this->errorServer(Yii::t('conquer/oauth2', 'The redirect URI provided does not match.'), Exception::INVALID_GRANT);
        }

        if (!empty($authCode->code_challenge)) {
            if (!$this->verifyCodeChallenge($authCode->code_challenge, $authCode->code_challenge_method)) {
                $this->errorServer(Yii::t('conquer/oauth2', 'The code verifier is invalid.'), Exception::INVALID_GRANT);
            }
            if ($this->client_secret !== null && $this->client_secret !== '') {
                $this->validateClientSecret('client_secret');
            }
        } else {
            $this->validateClientSecret('client_secret');
        }
    }

    /**
     * @param string $challenge
     * @param string|null $method
     * @return bool
     */
    protected function verifyCodeChallenge($challenge, $method)
    {
        if (!is_string($this->code_verifier) || $this->code_verifier === '') {
            return false;
        }
        if ($method === 'S256') {
            $computed = rtrim(strtr(base64_encode(hash('sha256', $this->code_verifier, true)), '+/', '-_'), '=');
        } else {
            $computed = $this->code_verifier;
        }
        return Yii::$app->security->compareString($challenge, $computed);
    }

    /**
     * @return array
     * @throws Exception
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
            'scope' => $authCode->scope,
            'refresh_token' => $refreshToken->refresh_token,
        ];
    }

    /**
     * @return AuthorizationCode
     * @throws Exception
     */
    public function getAuthCode()
    {
        if (is_null($this->_authCode)) {
            if (empty($this->code) || !is_string($this->code)) {
                $this->errorServer(Yii::t('conquer/oauth2', 'Authorization code is missing.'), Exception::INVALID_REQUEST);
            }
            if (!$this->_authCode = AuthorizationCode::findOne(['authorization_code' => $this->code])) {
                $this->errorServer(Yii::t('conquer/oauth2', 'The authorization code is not found or has been expired.'), Exception::INVALID_GRANT);
            }
        }
        return $this->_authCode;
    }
}
