<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2\services;

use conquer\oauth2\OAuth2;
use yii\web\BadRequestHttpException;
use yii\web\MethodNotAllowedHttpException;
use yii\web\Request;

/**
 * Class RequestService
 * @package conquer\oauth2\services
 * @author Andrey Borodulin
 */
class RequestService
{
    /**
     * @var Request
     */
    private $_request;
    private $_data;

    private $_clientId;
    private $_clientSecret;

    /**
     * RequestService constructor.
     * @throws MethodNotAllowedHttpException
     * @throws \yii\base\InvalidConfigException
     */
    public function __construct()
    {
        $this->_request = OAuth2::instance()->request;
        if ($this->_request->isPost) {
            $this->_data = $this->_request->post();
        } elseif ($this->_request->isGet) {
            $this->_data = $this->_request->get();
        } else {
            throw new MethodNotAllowedHttpException();
        }
        list($this->_clientId, $this->_clientSecret) = $this->_request->getAuthCredentials();
        if (!$this->_clientId) {
            $this->_clientId = $this->getParam('client_id');
        }
        if (!$this->_clientSecret) {
            $this->_clientSecret = $this->getParam('client_secret');
        }
    }

    /**
     * @return Request
     */
    public function getRequest()
    {
        return $this->_request;
    }

    /**
     * @param $name
     * @return string
     */
    public function getParam($name)
    {
        if (isset($this->_data[$name])) {
            return $this->_data[$name];
        }
        return null;
    }

    public function getState()
    {
        $state = $this->getParam('state');
        if (strlen($state) > 255) {
            throw new BadRequestHttpException('The state parameter is too long');
        }
        return $state;
    }

    /**
     * @param $name
     * @return string
     */
    public function getHeader($name)
    {
        return $this->_request->headers->get($name);
    }

    /**
     * @return array
     */
    public function getData()
    {
        return $this->_data;
    }

    /**
     * @return string
     */
    public function getClientId()
    {
        return $this->_clientId;
    }

    /**
     * @return string
     */
    public function getClientSecret()
    {
        return $this->_clientSecret;
    }
}
