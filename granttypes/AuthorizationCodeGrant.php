<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

use conquer\oauth2\models\AuthorizationCode;
use conquer\oauth2\models\Client;
/**
 *
 * @author Andrey Borodulin
 */
class AuthorizationCodeGrant extends GrantTypeAbstract
{
    private $_client;
    
    public $client_id;
    public $client_secret;
    public $code;
    public $redirect_uri;
    public $grant_type;
    public $state;
    
    
    public function rules()
    {
        return [
            [['client_id', 'client_secret', 'code', 'grant_type'], 'required'],
            [['client_id', 'client_secret'], 'string', 'max' => 80],
            [['code'], 'string', 'max' => 40],
            [['redirect_uri'], 'url'],
            [['grant_type'], 'in', 'range'=>['authorization_code']],
            [['code'], 'exist', 'targetClass' => AuthorizationCodeGrant::className(), 'targetAttribute'=>'authorization_code'],
            [['client_id'], 'exist', 'targetClass' => Client::className(), 'targetAttribute'=>'client_id'],
        ];
    }
    
    public function getClient()
    {
        if(empty($this->_client))
            $this->_client = Client::findOne($this->client_id);
        return $this->_client;
    }
    
}
