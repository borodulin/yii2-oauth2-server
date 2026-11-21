<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

/**
 * Builds redirect URIs of authorization responses.
 *
 * The registered redirect URI is kept as is (RFC 6749, 3.1.2: its query component MUST be retained);
 * it is not parsed and rebuilt, so app schemes (com.example.app:/cb) and loopback URIs stay intact.
 */
class Uri
{
    /**
     * Adds parameters to the query, or puts them in the fragment; an existing fragment is removed.
     * @param string $uri
     * @param string|array<string, mixed> $params a query string or parameters for http_build_query()
     * @param bool $fragment whether the parameters go in the fragment (implicit grant)
     * @return string
     */
    public static function withParams($uri, $params, $fragment = false)
    {
        $uri = (string)$uri;
        $hash = strpos($uri, '#');
        if ($hash !== false) {
            $uri = substr($uri, 0, $hash);
        }
        $query = is_array($params) ? http_build_query($params) : (string)$params;
        if ($query === '') {
            return $uri;
        }
        if ($fragment) {
            return $uri . '#' . $query;
        }
        $question = strpos($uri, '?');
        if ($question === false) {
            return $uri . '?' . $query;
        }
        $last = substr($uri, -1);
        return $uri . ($last === '?' || $last === '&' ? '' : '&') . $query;
    }
}
