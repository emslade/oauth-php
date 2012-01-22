<?php

use OAuth\OAuthRequest;

require dirname(__FILE__).'/../lib/OAuth/OAuth.php';
require dirname(__FILE__).'/../lib/OAuth/Exception.php';
require dirname(__FILE__).'/../lib/OAuth/Consumer.php';
require dirname(__FILE__).'/../lib/OAuth/Token.php';
require dirname(__FILE__).'/../lib/OAuth/Request.php';
require dirname(__FILE__).'/../lib/OAuth/Server.php';
require dirname(__FILE__).'/../lib/OAuth/DataStore.php';
require dirname(__FILE__).'/../lib/OAuth/Util.php';
require dirname(__FILE__).'/../lib/OAuth/SignatureMethod/SignatureMethod.php';
require dirname(__FILE__).'/../lib/OAuth/SignatureMethod/RSA_SHA1.php';
require dirname(__FILE__).'/../lib/OAuth/SignatureMethod/HMAC_SHA1.php';
require dirname(__FILE__).'/../lib/OAuth/SignatureMethod/PLAINTEXT.php';

/**
 * A simple utils class for methods needed
 * during some of the tests
 */
class OAuthTestUtils {
	private static function reset_request_vars() {
		$_SERVER = array();
		$_POST = array();
		$_GET = array();	
	}

	/**
	 * Populates $_{SERVER,GET,POST} and whatever environment-variables needed to test everything..
	 *
	 * @param string $method GET or POST
	 * @param string $uri What URI is the request to (eg http://example.com/foo?bar=baz)
	 * @param string $post_data What should the post-data be
	 * @param string $auth_header What to set the Authorization header to
	 */
	public static function build_request( $method, $uri, $post_data = '', $auth_header = '' ) {
		self::reset_request_vars();

		$method = strtoupper($method);

		$parts = parse_url($uri);

		$scheme = $parts['scheme'];
		$port   = isset( $parts['port'] ) && $parts['port'] ? $parts['port'] : ( $scheme === 'https' ? '443' : '80' );
		$host   = $parts['host'];
		$path   = isset( $parts['path'] )  ? $parts['path']  : NULL;
		$query  = isset( $parts['query'] ) ? $parts['query'] : NULL;

		if( $scheme == 'https') {
			$_SERVER['HTTPS'] = 'on';
		}

		$_SERVER['REQUEST_METHOD'] = $method;
		$_SERVER['HTTP_HOST'] = $host;
		$_SERVER['SERVER_NAME'] = $host;
		$_SERVER['SERVER_PORT'] = $port;
		$_SERVER['SCRIPT_NAME'] = $path;
		$_SERVER['REQUEST_URI'] = $path . '?' . $query;
		$_SERVER['QUERY_STRING'] = $query.'';
		parse_str($query, $_GET);

		if( $method == 'POST' ) {
			$_SERVER['HTTP_CONTENT_TYPE'] = 'application/x-www-form-urlencoded';
			$_POST = parse_str($post_data);
			OAuth\Request::$POST_INPUT = 'data:application/x-www-form-urlencoded,'.$post_data;
		}	
			
		if( $auth_header != '' ) {
			$_SERVER['HTTP_AUTHORIZATION'] = $auth_header;
		}
	}
}
