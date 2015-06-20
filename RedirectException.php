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
class RedirectException extends Exception
{
	
	/**
	 * @param string $redirect_uri 
	 * @param string $error_description (optional)
 	 * @param string $error A single error code
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
	 */
	public function __construct($redirect_uri, $error_description = null, $error = 'invalid_request')
	{
		parent::__construct($error_description, $error);
		
		$this->name = $error;
		
		$query = [ 'error' => $error];
		
		if($error_description)
		  $query['error_description'] = $error_description;
		
		$request = \Yii::$app->request;
		
		if($state = $request->get('state', $request->post('state')))
		    $query['state'] = $state;
		
		\Yii::$app->response->redirect(http_build_url($redirect_uri,[
	        PHP_URL_QUERY => $query  
		], HTTP_URL_REPLACE | HTTP_URL_JOIN_QUERY ));
	}	
}