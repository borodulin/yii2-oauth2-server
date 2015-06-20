<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\tokentypes;

use conquer\oauth2\OAuth2Trait;
/**
 * 
 * @author Andrey Borodulin
 */
class Bearer extends \yii\base\Model
{
    use OAuth2Trait;
    
    public $token;
    
    public function rules()
    {
        return [
            [['token'], 'validateBearerToken'],
        ];
    }
}