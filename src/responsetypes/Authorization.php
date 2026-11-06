<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\responsetypes;

use conquer\oauth2\models\AuthorizationCode;
use conquer\oauth2\BaseModel;

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
     * @var string
     */
    public $state;

    /**
     * PKCE code challenge (RFC 7636)
     * @var string
     */
    public $code_challenge;

    /**
     * PKCE code challenge method: "S256" or "plain" (default)
     * @var string
     */
    public $code_challenge_method;

    /**
     * @return array
     */
    public function rules()
    {
        return [
            [['response_type', 'client_id'], 'required'],
            ['response_type', 'required', 'requiredValue' => 'code'],
            [['client_id'], 'string', 'max' => 80],
            [['state'], 'string', 'max' => 255],
            [['redirect_uri'], 'url'],
            [['client_id'], 'validateClientId'],
            [['redirect_uri'], 'validateAuthorizationRedirectUri', 'skipOnEmpty' => false],
            [['code_challenge'], 'string', 'min' => 43, 'max' => 128],
            [['code_challenge_method'], 'in', 'range' => ['S256', 'plain']],
            [['scope'], 'validateScope'],
        ];
    }

    /**
     * @return array
     * @throws \conquer\oauth2\Exception
     * @throws \yii\base\Exception
     */
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

        if (isset($this->state)) {
            $query['state'] = $this->state;
        }

        return [
            'query' => http_build_query($query),
        ];
    }
}
