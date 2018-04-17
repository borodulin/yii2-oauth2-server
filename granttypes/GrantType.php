<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

use yii\base\Model;

/**
 * Class GrantType
 * @package conquer\oauth2\granttypes
 */
class GrantType extends Model
{

    const AUTHORIZATION_CODE = 'authorization_code';
    const REFRESH_TOKEN = 'refresh_token';
    const CLIENT_CREDENTIALS = 'client_credentials';
    const PASSWORD = 'password';
    const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    /**
     * @var string
     */
    public $grant_type;

    public $allowedGrantTypes = [
        self::AUTHORIZATION_CODE,
        self::REFRESH_TOKEN,
    ];

    /**
     * @return array
     */
    public function rules()
    {
        return [
            [['grant_type'], 'required'],
            [['grant_type'], 'in', 'range' => $this->allowedGrantTypes],
        ];
    }
}
