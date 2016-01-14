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

    public function rules()
    {
        return [
            [['response_type', 'client_id'], 'required'],
            ['response_type', 'required', 'requiredValue' => 'code'],
            [['client_id'], 'string', 'max' => 80],
            [['state'], 'string', 'max' => 255],
            [['redirect_uri'], 'url'],
            [['client_id'], 'validateClient_id'],
            [['redirect_uri'], 'validateRedirect_uri'],
            [['scope'], 'validateScope'],
        ];
    }
    
    public function getResponseData()
    {
        $authCode = AuthorizationCode::createAuthorizationCode([
            'client_id' => $this->client_id,
            'user_id' => \Yii::$app->user->id,
            'expires' => $this->authCodeLifetime+time(),
            'scope' => $this->scope,
            'redirect_uri' => $this->redirect_uri
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


