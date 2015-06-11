<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;

use Yii;
use yii\web\Controller;
use yii\web\Response;
use conquer\oauth2\models\OauthAccessToken;

/**
 * 
 * @author Andrey Borodulin
 * 
 */
class OauthFilter extends \yii\base\ActionFilter
{
    
    public $tokenType = 'Bearer';

    /**
     * @inheritdoc
     */
    public function beforeAction($action)
    {
        \Yii::$app->response->format = Response::FORMAT_JSON;
        /* @var $accessToken \conquer\oauth2\models\OauthAccessToken */
        $accessToken = OauthAccessToken::findOne(['access_token' => $this->getAccessToken()]);
        if($accessToken->expires < time())
            throw new OauthException('The access token provided has expired', 'expired_token');
        
        return true;
    }
    
    /**
     * This is a convenience function that can be used to get the token, which can then
     * be passed to verifyAccessToken(). The constraints specified by the draft are
     * attempted to be adheared to in this method.
     *
     * As per the Bearer spec (draft 8, section 2) - there are three ways for a client
     * to specify the bearer token, in order of preference: Authorization Header,
     * POST and GET.
     *
     * NB: Resource servers MUST accept tokens via the Authorization scheme
     * (http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2).
     *
     * @todo Should we enforce TLS/SSL in this function?
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3
     *
     * Old Android version bug (at least with version 2.2)
     * @see http://code.google.com/p/android/issues/detail?id=6684
     *
     * We don't want to test this functionality as it relies on superglobals and headers:
     * @codeCoverageIgnoreStart
     */
    public function getAccessToken() {
        
        $request = \Yii::$app->request;
        if($request->headers->has('authorization')){
            $header = $request->headers->get('authorization');
        } else
            $header = null;

        $postToken = $request->post($this->tokenType);        
        $getToken = $request->get($this->tokenType);
        
        // Check that exactly one method was used
        $methodsUsed = !empty($header) + !empty($postToken) + !empty($getToken);
        if ($methodsUsed > 1) {
            throw new OauthException('Only one method may be used to authenticate at a time (Auth header, POST or GET).');
        } elseif ($methodsUsed == 0) {
            throw new OauthException('The access token was not found.');
        }
        
        // HEADER: Get the access token from the header
        if (!empty($header)) {
            if (preg_match("/{$this->tokenType} (\S+)/", $header, $matches))
                return $matches[1];
            else
                throw new OauthException('Malformed auth header.');
        }
    
        // POST: Get the token from POST data
        if ($postToken) {
            if(!$request->isPost)
                throw new OauthException('When putting the token in the body, the method must be POST.');
            
            // IETF specifies content-type. NB: Not all webservers populate this _SERVER variable
            if($request->contentType != 'application/x-www-form-urlencoded')
                throw new OauthException('The content type for POST requests must be "application/x-www-form-urlencoded"');
            
            return $postToken;
        }
        
        return $getToken;
    }
}
