<?php
/**
 * @link https://github.com/borodulin/yii2-oauth-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth-server/blob/master/LICENSE
 */

namespace conquer\oauth2;


use yii\web\Response;

/**
 * 
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1
 *
 * @author Andrey Borodulin
 * 
 */
class Oauth2RedirectException extends OauthException
{
	
	protected $redirectUri;

	protected $name;
	
	/**
	 * @param string $redirect_uri 
	 * @param string $error A single error code as described in Section 4.1.2.1
	 * @param string $error_description (optional)
	 * @param string $state (optional) 
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
	 */
	public function __construct($redirect_uri, $error_description = null, $state = null, $error = 'invalid_request')
	{
		parent::__construct($error_description, $error);
		
		$this->name = $error;
		
		$query = [
	        'error' => $error,
		];
		
		if($error_description)
		  $query['error_description'] = $error_description;
		
		if($state)
		    $query['state'] = $state;
		
		\Yii::$app->response->redirect(http_build_url($redirect_uri,[
	        PHP_URL_QUERY => $query  
		], HTTP_URL_REPLACE | HTTP_URL_JOIN_QUERY ));
	}
	
	/**
	 * @return string the user-friendly name of this exception
	 */
	public function getName()
	{
	    if(isset($this->name))
	        return $this->name;
	    if (isset(Response::$httpStatuses[$this->statusCode])) {
	        return Response::$httpStatuses[$this->statusCode];
	    } else {
	        return 'Error';
	    }
	}
	
}