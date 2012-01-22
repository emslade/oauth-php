<?php

use OAuth\Consumer;

require 'common.php';

class ConsumerTest extends PHPUnit_Framework_TestCase {
	public function testConvertToString() {
		$consumer = new Consumer('key', 'secret');
		$this->assertEquals('OAuthConsumer[key=key,secret=secret]', (string) $consumer);
	}
}
