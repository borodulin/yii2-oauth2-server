<?php
/**
 * Created by PhpStorm.
 * User: borodulin
 * Date: 19.04.18
 * Time: 19:17
 */

namespace conquer\oauth2\responsetypes;

use conquer\oauth2\models\AuthorizationCode;
use conquer\oauth2\services\ClientService;
use Yii;

/**
 * Class AuthorizationResponse
 * @package conquer\oauth2\responsetypes
 */
class AuthorizationResponse implements ResponseTypeInterface
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
     * @var ClientService
     */
    private $clientService;

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
            [['redirect_uri'], 'validateRedirectUri'],
            [['scope'], 'validateScope'],
        ];
    }

    public function __construct(ClientService $clientService)
    {
        $this->clientService = $clientService;
    }


    /**
     * @return array
     * @throws \conquer\oauth2\Exception
     * @throws \yii\base\Exception
     */
    public function getResponseData()
    {
        $this->clientService->validateRedirectUri();
        $this->clientService->validateScope();

        $authCode = AuthorizationCode::create($this->clientService->client->client_id, Yii::$app->user->id, $this->scope);

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