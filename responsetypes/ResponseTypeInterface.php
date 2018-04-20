<?php
/**
 * Created by PhpStorm.
 * User: borodulin
 * Date: 20.04.18
 * Time: 14:44
 */

namespace conquer\oauth2\responsetypes;


interface ResponseTypeInterface
{
    /**
     * @return array
     */
    public function getResponseData();
}