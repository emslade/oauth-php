<?php

use OAuth\Token;

require_once 'common.php';

class TokenTest extends PHPUnit_Framework_TestCase {
	public function testSerialize() {
		$token = new Token('token', 'secret');
		$this->assertEquals('oauth_token=token&oauth_token_secret=secret', $token->to_string());
		
		$token = new Token('token&', 'secret%');
		$this->assertEquals('oauth_token=token%26&oauth_token_secret=secret%25', $token->to_string());
	}
	public function testConvertToString() {
		$token = new Token('token', 'secret');
		$this->assertEquals('oauth_token=token&oauth_token_secret=secret', (string) $token);
		
		$token = new Token('token&', 'secret%');
		$this->assertEquals('oauth_token=token%26&oauth_token_secret=secret%25', (string) $token);
	}
}
