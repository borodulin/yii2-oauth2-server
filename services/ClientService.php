<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\services;

use conquer\oauth2\Exception;
use conquer\oauth2\models\Client;
use conquer\oauth2\RedirectException;
use Yii;
use yii\web\BadRequestHttpException;

/**
 * Class ClientService
 * @package conquer\oauth2\services
 * @author Andrey Borodulin
 */
class ClientService
{

    /**
     * @var Client
     */
    public $client;

    /**
     * @var
     */
    private $requestService;

    /**
     * ClientService constructor.
     * @param RequestService $requestService
     * @throws BadRequestHttpException
     */
    public function __construct(RequestService $requestService)
    {
        $this->requestService = $requestService;
        if (!$this->client = Client::findOne(['client_id' => $requestService->getClientId()])) {
            throw new BadRequestHttpException('Unknown client');
        }
    }

    /**
     * @throws Exception
     * @throws RedirectException
     */
    public function validateScope()
    {
        $state = $this->requestService->getParam('state');
        $scope = $this->requestService->getParam('scope');
        $redirectUri = $this->requestService->getParam('redirect_uri');
        if (!$this->checkSets($scope, $this->client->scope)) {
            $redirectUri = isset($redirectUri) ? $redirectUri : $this->client->redirect_uri;
            if ($redirectUri) {
                throw new RedirectException($redirectUri, 'The requested scope is invalid, unknown, or malformed.', Exception::INVALID_SCOPE, $state);
            } else {
                throw new Exception('The requested scope is invalid, unknown, or malformed.', Exception::INVALID_SCOPE);
            }
        }
    }

    /**
     * @throws BadRequestHttpException
     */
    public function validateRedirectUri()
    {
        $redirectUri = $this->requestService->getParam('redirect_uri');
        $clientRedirectUri = $this->client->redirect_uri;
        if (strncasecmp($redirectUri, $clientRedirectUri, strlen($clientRedirectUri)) !== 0) {
            throw new BadRequestHttpException('The redirect URI provided is missing or does not match');
        }
    }

    /**
     * @param $clientSecret
     * @throws Exception
     */
    public function validateClientSecret()
    {
        $clientSecret = $this->requestService->getClientSecret();
        if (!Yii::$app->security->compareString($this->client->client_secret, $clientSecret)) {
            throw new Exception('The client credentials are invalid', Exception::UNAUTHORIZED_CLIENT);
        }
    }

    public function validateGrantType()
    {

    }

    /**
     * Checks if everything in required set is contained in available set.
     *
     * @param string|array $requiredSet
     * @param string|array $availableSet
     * @return boolean
     */
    public function checkSets($requiredSet, $availableSet)
    {
        if (!is_array($requiredSet)) {
            $requiredSet = explode(' ', trim($requiredSet));
        }
        if (!is_array($availableSet)) {
            $availableSet = explode(' ', trim($availableSet));
        }
        return (count(array_diff($requiredSet, $availableSet)) == 0);
    }
}
