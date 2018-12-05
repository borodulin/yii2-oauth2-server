<?php

namespace conquer\oauth2\request;

use conquer\oauth2\Exception;
use Yii;
use yii\web\Request;

/**
 * Class AccessTokenExtractor
 * @package conquer\oauth2\request
 */
class AccessTokenExtractor
{
    /**
     * @var Request
     */
    private $_request;

    /**
     * AccessTokenExtractor constructor.
     * @param Request $request
     */
    public function __construct(Request $request)
    {
        $this->_request = $request;
    }

    /**
     * Extracts access_token from web request
     * @return string
     * @throws Exception
     */
    public function extract()
    {
        $headerToken = null;
        foreach ($this->_request->getHeaders()->get('Authorization', [], false) as $authHeader) {
            if (preg_match('/^Bearer\\s+(.*?)$/', $authHeader, $matches)) {
                $headerToken = $matches[1];
                break;
            }
        }
        $postToken = $this->_request->post('access_token');
        $getToken = $this->_request->get('access_token');

        // Check that exactly one method was used
        $methodsCount = isset($headerToken) + isset($postToken) + isset($getToken);
        if ($methodsCount > 1) {
            throw new Exception(Yii::t('conquer/oauth2', 'Only one method may be used to authenticate at a time (Auth header, POST or GET).'));
        } elseif ($methodsCount === 0) {
            throw new Exception(Yii::t('conquer/oauth2', 'The access token was not found.'));
        }

        // HEADER: Get the access token from the header
        if ($headerToken) {
            return $headerToken;
        }

        // POST: Get the token from POST data
        if ($postToken) {
            if (!$this->_request->isPost) {
                throw new Exception(Yii::t('conquer/oauth2', 'When putting the token in the body, the method must be POST.'));
            }
            // IETF specifies content-type. NB: Not all webservers populate this _SERVER variable
            if (strpos($this->_request->contentType, 'application/x-www-form-urlencoded') !== 0) {
                throw new Exception(Yii::t('conquer/oauth2', 'The content type for POST requests must be "application/x-www-form-urlencoded".'));
            }
            return $postToken;
        }

        return $getToken;
    }
}
