<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

use conquer\oauth2\BaseModel;
use conquer\oauth2\Exception;

/**
 *
 * @link http://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-04#section-4
 *
 * @author Andrey Borodulin
 */
class JwtBearer extends BaseModel
{

    /**
     * @return never
     * @throws Exception
     */
    public function getResponseData()
    {
        throw new Exception('The JWT bearer grant type is not implemented.', Exception::NOT_IMPLEMENTED);
    }
}
