<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

/**
 * An authorization endpoint error that is reported to the client by redirecting the user agent
 * to the redirect URI (RFC 6749, 4.1.2.1 and 4.2.2.1). AuthorizeFilter catches it and sends the redirect.
 *
 * @link https://tools.ietf.org/html/rfc6749#section-4.1.2.1
 * @author Andrey Borodulin
 */
class RedirectException extends Exception
{
    /**
     * @var string
     */
    private $_redirectUri;

    /**
     * @param string $redirect_uri the client redirect URI
     * @param string|null $error_description
     * @param string $error A single error code
     * @param string|null $state the state parameter of the request
     * @param bool $fragment whether the error is sent in the fragment (implicit grant) instead of the query
     * @param string|null $issuer the "iss" parameter (RFC 9207)
     */
    public function __construct($redirect_uri, $error_description = null, $error = self::INVALID_REQUEST, $state = null, $fragment = false, $issuer = null)
    {
        parent::__construct($error_description, $error);

        $params = ['error' => $error];
        if ($error_description) {
            $params['error_description'] = $error_description;
        }
        if ($state !== null && $state !== '') {
            $params['state'] = $state;
        }
        if ($issuer !== null && $issuer !== '') {
            $params['iss'] = $issuer;
        }
        $this->_redirectUri = self::buildUri($redirect_uri, $params, $fragment);
    }

    /**
     * @return string the URI the user agent must be redirected to
     */
    public function getRedirectUri()
    {
        return $this->_redirectUri;
    }

    /**
     * Adds parameters to the query or to the fragment of a URI; an existing fragment is removed (RFC 6749, 3.1.2).
     * @param string $uri
     * @param array<string, mixed> $params
     * @param bool $fragment
     * @return string
     */
    public static function buildUri($uri, array $params, $fragment = false)
    {
        $query = http_build_query($params);
        if ($fragment) {
            return http_build_url($uri, [], HTTP_URL_STRIP_FRAGMENT) . '#' . $query;
        }
        return http_build_url($uri, ['query' => $query], HTTP_URL_JOIN_QUERY | HTTP_URL_STRIP_FRAGMENT);
    }
}
