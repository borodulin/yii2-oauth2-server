<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\responsetypes;

use conquer\oauth2\models\AccessToken;
use conquer\oauth2\BaseModel;

/**
 * @link https://tools.ietf.org/html/rfc6749#section-4.2.1
 * @author Andrey Borodulin
 */
class Implicit extends BaseModel
{
    /**
     * Access Token lifetime
     * 1 hour by default
     * @var integer
     */
    public $accessTokenLifetime = 3600;

    /**
     * Value MUST be set to "token"
     * @var string
     */
    public $response_type;

    /**
     * The client identifier as described in Section 2.2.
     * @link https://tools.ietf.org/html/rfc6749#section-2.2
     * @var string
     */
    public $client_id;

    /**
     * As described in Section 3.1.2.
     * @link https://tools.ietf.org/html/rfc6749#section-3.1.2
     * @var string
     */
    public $redirect_uri;

    /**
     * The scope of the access request as described by Section 3.3.
     * @link https://tools.ietf.org/html/rfc6749#section-3.3
     * @var string
     */
    public $scope;

    /**
     * The parameter SHOULD be used for preventing cross-site request forgery as described in Section 10.12.
     * @link https://tools.ietf.org/html/rfc6749#section-10.12
     * @var string
     */
    public $state;

    /**
     * @return array
     */
    public function rules()
    {
        return [
            [['client_id', 'response_type'], 'required'],
            ['response_type', 'required', 'requiredValue' => 'token'],
            [['client_id'], 'string', 'max' => 80],
            [['state'], 'string', 'max' => 255],
            [['redirect_uri'], 'url'],
            [['client_id'], 'validateClientId'],
            [['redirect_uri'], 'validateRedirectUri'],
            [['scope'], 'validateScope'],

        ];
    }

    /**
     * @return array
     * @throws \conquer\oauth2\Exception
     * @throws \yii\base\Exception
     */
    public function getResponseData()
    {
        $accessToken = AccessToken::createAccessToken([
            'client_id' => $this->client_id,
            'user_id' => \Yii::$app->user->id,
            'expires' => $this->accessTokenLifetime + time(),
            'scope' => $this->scope,
        ]);

        $fragment = [
            'access_token' => $accessToken->access_token,
            'expires_in' => $this->accessTokenLifetime,
            'token_type' => $this->tokenType,
            'scope' => $this->scope,
        ];

        if (!empty($this->state)) {
            $fragment['state'] = $this->state;
        }
        return [
            'fragment' => http_build_query($fragment),
        ];
    }
}
