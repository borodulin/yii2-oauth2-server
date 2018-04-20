<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\granttypes;

/**
 * Interface GrantInterface
 * @package conquer\oauth2\granttypes
 * @author Andrey Borodulin
 */
interface GrantInterface
{
    /**
     * @return array
     */
    public function getResponseData();
}