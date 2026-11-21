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
     * @var bool
     */
    private $_allowQuery;

    /**
     * AccessTokenExtractor constructor.
     * @param Request $request
     * @param bool $allowQuery whether the access_token query parameter is accepted. Tokens in URLs end up in logs,
     * browser history and Referer headers (RFC 6750, 2.3; RFC 9700, 2.4.2).
     */
    public function __construct(Request $request, $allowQuery = false)
    {
        $this->_request = $request;
        $this->_allowQuery = $allowQuery;
    }

    /**
     * Extracts access_token from web request
     * @param bool $required whether to throw an exception when the request has no access token;
     * when false, null is returned instead
     * @return string|null
     * @throws Exception
     */
    public function extract($required = true)
    {
        $headerToken = null;
        foreach ($this->_request->getHeaders()->get('Authorization', [], false) as $authHeader) {
            // the scheme is case-insensitive (RFC 7235, 2.1)
            if (preg_match('/^Bearer\\s+(.*?)$/i', $authHeader, $matches)) {
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
            if (!$required) {
                return null;
            }
            throw new Exception(Yii::t('conquer/oauth2', 'The access token was not found.'));
        }

        if (!is_string($headerToken ?? $postToken ?? $getToken)) {
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

        if (!$this->_allowQuery) {
            throw new Exception(Yii::t('conquer/oauth2', 'The access token must not be sent in the URL.'));
        }
        return $getToken;
    }
}
