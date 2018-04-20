<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\responsetypes;

use conquer\oauth2\models\AccessToken;
use conquer\oauth2\OAuth2;
use conquer\oauth2\services\ClientService;
use conquer\oauth2\services\RequestService;
use JsonSerializable;
use Yii;
use yii\web\ServerErrorHttpException;

/**
 * Class ImplicitResponse
 * @package conquer\oauth2\responsetypes
 * @author Andrey Borodulin
 */
class ImplicitResponse implements ResponseTypeInterface, JsonSerializable
{
    /**
     * @var ClientService
     */
    private $_clientService;

    /**
     * @var RequestService
     */
    private $_requestService;

    private $_clientId;
    private $_scope;
    private $_state;

    /**
     * ImplicitResponse constructor.
     * @param ClientService $clientService
     * @param RequestService $requestService
     * @param array $params
     */
    public function __construct(ClientService $clientService, RequestService $requestService, $params = [])
    {
        $this->_clientService = $clientService;
        $this->_requestService = $requestService;
        $this->_state = isset($params['state']) ? $params['state'] : null;
        $this->_scope = isset($params['scope']) ? $params['scope'] : null;
        $this->_clientId = isset($params['client_id']) ? $params['client_id'] : null;
    }

    public function validate()
    {
        $this->_state = $this->_requestService->getState();

        $this->_clientService->validateRedirectUri();
        $this->_clientService->validateScope();

        $this->_scope = $this->_requestService->getParam('scope');

        $this->_clientId = $this->_clientService->client->client_id;
    }

    /**
     * @return array
     * @throws ServerErrorHttpException
     * @throws \yii\base\Exception
     * @throws \yii\base\InvalidConfigException
     */
    public function getResponseData()
    {
        if (!isset($this->_clientId)) {
            throw new ServerErrorHttpException('Invalid call.');
        }
        $accessToken = AccessToken::create(
            $this->_clientId,
            Yii::$app->user->id,
            $this->_scope
        );

        $oauth2 = OAuth2::instance();

        $fragment = [
            'access_token' => $accessToken->access_token,
            'expires_in' => $oauth2->accessTokenLifetime,
            'token_type' => $oauth2->tokenType,
            'scope' => $this->_scope,
        ];

        if ($this->_state) {
            $fragment['state'] = $this->_state;
        }

        return [
            'fragment' => http_build_query($fragment),
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
        ];
    }
}
