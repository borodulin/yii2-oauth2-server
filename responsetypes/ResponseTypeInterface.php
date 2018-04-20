<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\responsetypes;

/**
 * Interface ResponseTypeInterface
 * @package conquer\oauth2\responsetypes
 * @author Andrey Borodulin
 */
interface ResponseTypeInterface
{

    public function validate();

    /**
     * @return array
     */
    public function getResponseData();
}
