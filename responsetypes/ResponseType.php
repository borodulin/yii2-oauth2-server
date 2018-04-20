<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\responsetypes;

use yii\base\Model;

/**
 * Class ResponseType
 * @package conquer\oauth2\responsetypes
 */
class ResponseType extends Model
{
    const AUTHORIZATION_CODE = 'code';
    const IMPLICIT_TOKEN = 'token';


    /**
     * Value MUST be set to "token"
     * @var string
     */
    public $response_type;


    public $allowedResponseTypes = [
        self::AUTHORIZATION_CODE,
        self::IMPLICIT_TOKEN,
    ];

    /**
     * @return array
     */
    public function rules()
    {
        return [
            [['response_type'], 'required'],
            [['response_type'], 'in', 'range' => $this->allowedResponseTypes],
        ];
    }
}
