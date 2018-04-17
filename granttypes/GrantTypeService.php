<?php
/**
 * Created by PhpStorm.
 * User: borodulin
 * Date: 16.04.18
 * Time: 19:32
 */

namespace conquer\oauth2\granttypes;


use conquer\oauth2\Exception;
use conquer\oauth2\OAuth2;
use yii\base\Model;
use yii\web\MethodNotAllowedHttpException;
use yii\web\Request;

class GrantTypeService
{
    public static $grantTypeMap = [
        GrantType::AUTHORIZATION_CODE => AuthorizationGrant::class,
        GrantType::REFRESH_TOKEN => RefreshTokenGrant::class,
        GrantType::CLIENT_CREDENTIALS => ClientCredentialsGrant::class,
        GrantType::PASSWORD => UserCredentialsGrant::class,
        GrantType::JWT_BEARER => JwtBearerGrant::class,
    ];

    /**
     * @param Request $request
     * @return Model
     * @throws Exception
     * @throws MethodNotAllowedHttpException
     * @throws \yii\base\InvalidConfigException
     */
    public function create(Request $request)
    {
        $data = OAuth2::instance()->getRequestData($request);
        $grantType = new GrantType();
        $grantType->attributes = $data;
        if (!$grantType->validate()) {
            throw new Exception($grantType->getFirstError('grant_type'), Exception::INVALID_GRANT);
        }

        if (isset(self::$grantTypeMap[$grantType->grant_type])) {
            $className = self::$grantTypeMap[$grantType->grant_type];
            /** @var Model $grant */
            $grant = new $className;
            $grant->attributes = $data;
            if (!$grant->validate()) {
                throw new Exception('TODO');
            }
            return $grant;
        }
        throw new Exception('TODO');
    }
}