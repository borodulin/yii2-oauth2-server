<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\responsetypes;

use conquer\oauth2\models\AuthorizationCode;
use conquer\oauth2\BaseModel;
use conquer\oauth2\Exception;

/**
 * @link https://tools.ietf.org/html/rfc6749#section-4.1.1
 * @author Andrey Borodulin
 */
class Authorization extends BaseModel
{
    /**
     * Value MUST be set to "code".
     * @var string
     */
    public $response_type;
    /**
     * Client Identifier
     * @link https://tools.ietf.org/html/rfc6749#section-2.2
     * @var string
     */
    public $client_id;
    /**
     * Redirection Endpoint
     * @link https://tools.ietf.org/html/rfc6749#section-3.1.2
     * @var string
     */
    public $redirect_uri;
    /**
     * Access Token Scope
     * @link https://tools.ietf.org/html/rfc6749#section-3.3
     * @var string
     */
    public $scope;
    /**
     * Cross-Site Request Forgery
     * @link https://tools.ietf.org/html/rfc6749#section-10.12
     * @var string|null
     */
    public $state;

    /**
     * PKCE code challenge (RFC 7636)
     * @var mixed raw request value, checked in validateCodeChallenge()
     */
    public $code_challenge;

    /**
     * PKCE code challenge method: "S256", or "plain" when [[allowPlainPkce]] is enabled.
     * Omitted means "plain" (RFC 7636, 4.3).
     * @var string
     */
    public $code_challenge_method;

    /**
     * @var bool whether the "plain" PKCE method is accepted. With "plain" the verifier equals the challenge,
     * which travels in the front channel, so it does not protect against code interception (RFC 9700, 2.1.1).
     */
    public $allowPlainPkce = false;

    /**
     * @var bool whether PKCE is required for all clients. It is always required for public clients.
     */
    public $requirePkce = false;

    public function rules()
    {
        return [
            [['response_type', 'client_id'], 'required'],
            ['response_type', 'required', 'requiredValue' => 'code'],
            [['client_id'], 'string', 'max' => 80],
            [['state'], 'string', 'max' => 255],
            // exact match with a registered URI; no url validator, which rejects http://localhost and app schemes
            [['redirect_uri', 'scope'], 'string'],
            [['client_id'], 'validateClientId'],
            [['redirect_uri'], 'validateAuthorizationRedirectUri', 'skipOnEmpty' => false],
            [['response_type'], 'validateGrantType'],
            [['code_challenge_method'], 'in', 'range' => ['S256', 'plain']],
            [['code_challenge'], 'validateCodeChallenge', 'skipOnEmpty' => false],
            [['scope'], 'validateScope'],
        ];
    }

    /**
     * @return void
     * @throws \conquer\oauth2\Exception
     */
    public function validateGrantType()
    {
        $this->checkResponseGrantType('authorization_code');
    }

    /**
     * Validates the PKCE code challenge (RFC 7636, 4.2).
     * @return void
     * @throws \conquer\oauth2\Exception
     */
    public function validateCodeChallenge()
    {
        if ($this->code_challenge === null || $this->code_challenge === '') {
            if ($this->requirePkce || $this->getClient()->isPublic()) {
                $this->errorRedirect(\Yii::t('conquer/oauth2', 'PKCE code challenge is required.'), Exception::INVALID_REQUEST);
            }
            return;
        }
        $method = $this->code_challenge_method ?: 'plain';
        if ($method === 'plain' && !$this->allowPlainPkce) {
            $this->errorRedirect(\Yii::t('conquer/oauth2', 'The code challenge method must be S256.'), Exception::INVALID_REQUEST);
        }
        $pattern = $method === 'S256' ? '/^[A-Za-z0-9_-]{43}$/' : '/^[A-Za-z0-9\-._~]{43,128}$/';
        if (!is_string($this->code_challenge) || !preg_match($pattern, $this->code_challenge)) {
            $this->errorRedirect(\Yii::t('conquer/oauth2', 'The code challenge is invalid.'), Exception::INVALID_REQUEST);
        }
    }

    /**
     * @inheritdoc
     */
    protected function redirectsErrors()
    {
        return true;
    }

    public function getResponseData()
    {
        $authCode = AuthorizationCode::createAuthorizationCode([
            'client_id' => $this->client_id,
            'user_id' => \Yii::$app->user->id,
            'expires' => $this->authCodeLifetime + time(),
            'scope' => $this->scope,
            // redirect_uri is bound to the code only when it was included in the request (RFC 6749, 4.1.3)
            'redirect_uri' => $this->_redirectUriFromClient ? '' : (string)$this->redirect_uri,
            'code_challenge' => $this->code_challenge,
            'code_challenge_method' => $this->code_challenge ? ($this->code_challenge_method ?: 'plain') : null,
        ]);

        $query = [
            'code' => $authCode->authorization_code,
        ];

        if ($this->state !== null && $this->state !== '') {
            $query['state'] = $this->state;
        }
        if ($this->issuer !== null) {
            $query['iss'] = $this->issuer;
        }

        return [
            'query' => http_build_query($query),
        ];
    }
}
