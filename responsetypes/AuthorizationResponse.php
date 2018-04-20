<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\responsetypes;

use conquer\oauth2\models\AuthorizationCode;
use conquer\oauth2\services\ClientService;
use conquer\oauth2\services\RequestService;
use JsonSerializable;
use Yii;
use yii\web\ServerErrorHttpException;

/**
 * Class AuthorizationResponse
 * @package conquer\oauth2\responsetypes
 * @author Andrey Borodulin
 */
class AuthorizationResponse implements ResponseTypeInterface, JsonSerializable
{
    /**
     * @var ClientService
     */
    private $_clientService;

    /**
     * @var RequestService
     */
    private $_requestService;

    private $_redirectUri;
    private $_state;
    private $_clientId;
    private $_scope;


    /**
     * AuthorizationResponse constructor.
     * @param ClientService $clientService
     * @param RequestService $requestService
     * @param array $params
     */
    public function __construct(ClientService $clientService, RequestService $requestService, $params = [])
    {
        $this->_clientService = $clientService;
        $this->_requestService = $requestService;
        $this->_redirectUri = isset($params['redirect_uri']) ? $params['redirect_uri'] : null;
        $this->_state = isset($params['state']) ? $params['state'] : null;
        $this->_scope = isset($params['scope']) ? $params['scope'] : null;
        $this->_clientId = isset($params['client_id']) ? $params['client_id'] : null;
    }

    public function validate()
    {
        $this->_state = $this->_requestService->getState();

        $this->_clientService->validateRedirectUri();
        $this->_clientService->validateScope();

        $this->_clientId = $this->_clientService->client->client_id;

        $this->_scope = $this->_requestService->getParam('scope');
    }

    /**
     * @return array
     * @throws \conquer\oauth2\Exception
     * @throws \yii\base\Exception
     */
    public function getResponseData()
    {
        if (!isset($this->_clientId)) {
            throw new ServerErrorHttpException('Invalid call');
        }
        $authCode = AuthorizationCode::create(
            $this->_clientId,
            Yii::$app->user->id,
            $this->_scope,
            $this->_redirectUri
        );

        $query = [
            'code' => $authCode->authorization_code,
        ];

        if ($this->_state) {
            $query['state'] = $this->_state;
        }

        return [
            'query' => http_build_query($query),
        ];
    }

    /**
     * Specify data which should be serialized to JSON
     * @link http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     * @since 5.4.0
     */
    public function jsonSerialize()
    {
        return [
            'client_id' => $this->_clientId,
            'scope' => $this->_scope,
            'state' => $this->_state,
            'redirect_uri' => $this->_redirectUri,
        ];
    }
}
