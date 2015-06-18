<?php
/**
 * @link https://github.com/borodulin/yii2-oauth2-server
 * @copyright Copyright (c) 2015 Andrey Borodulin
 * @license https://github.com/borodulin/yii2-oauth2-server/blob/master/LICENSE
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
class Oauth2RedirectException extends Oauth2Exception
{
	
	protected $redirectUri;

	protected $name;
	
	/**
	 * @param string $redirectUri 
	 * @param string $error
	 * @param string $errorDescription (optional)
	 * @param string $state (optional) 
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
	 */
	public function __construct($redirectUri, $errorDescription = null, $state = null, $error = 'invalid_request')
	{
		parent::__construct($errorDescription, $error);
		
		$this->name = $error;
		
		$query = [
	        'error' => $error,
		];
		
		if($errorDescription)
		  $query['error_description'] = $errorDescription;

// 		$state = isset($_POST['state']) ? $_POST['state'] : (isset($_GET['state']) ? $_GET['state'] : null);
		
		if($state)
		    $query['state'] = $state;
		
		\Yii::$app->response->redirect(http_build_url($redirect_uri,[
	        PHP_URL_QUERY => http_build_query($query)  
		], HTTP_URL_JOIN_QUERY));
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