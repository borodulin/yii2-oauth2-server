<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\services;
use conquer\oauth2\granttypes\AuthorizationGrant;
use conquer\oauth2\granttypes\ClientCredentialsGrant;
use conquer\oauth2\granttypes\GrantInterface;
use conquer\oauth2\granttypes\JwtBearerGrant;
use conquer\oauth2\granttypes\RefreshTokenGrant;
use conquer\oauth2\granttypes\UserCredentialsGrant;
use Yii;
use yii\web\ServerErrorHttpException;

/**
 * Class GrantTypeService
 * @package conquer\oauth2\services
 * @author Andrey Borodulin
 */
class GrantTypeService
{
    const AUTHORIZATION_CODE = 'authorization_code';
    const REFRESH_TOKEN = 'refresh_token';
    const CLIENT_CREDENTIALS = 'client_credentials';
    const PASSWORD = 'password';
    const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    public static $grantTypeMap = [
        self::AUTHORIZATION_CODE => AuthorizationGrant::class,
        self::REFRESH_TOKEN => RefreshTokenGrant::class,
        self::CLIENT_CREDENTIALS => ClientCredentialsGrant::class,
        self::PASSWORD => UserCredentialsGrant::class,
        self::JWT_BEARER => JwtBearerGrant::class,
    ];

    /**
     * @var ClientService
     */
    private $clientService;

    /**
     * @var RequestService
     */
    private $requestService;

    public function __construct(ClientService $clientService, RequestService $requestService)
    {
        $this->clientService = $clientService;
        $this->requestService = $requestService;
    }

    /**
     * @return array
     * @throws ServerErrorHttpException
     * @throws \yii\base\InvalidConfigException
     */
    public function getResponseData()
    {
        $this->clientService->validateGrantType();
        $grantType = $this->requestService->getParam('grant_type');

        if (isset(self::$grantTypeMap[$grantType])) {
            $className = self::$grantTypeMap[$grantType];
            /** @var GrantInterface $grant */
            $grant = Yii::createObject($className);
            return $grant->getResponseData();
        }
        throw new ServerErrorHttpException('Invalid grant type');
    }

}
