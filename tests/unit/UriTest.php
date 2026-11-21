<?php

namespace tests\unit;

use conquer\oauth2\Uri;

class UriTest extends \Codeception\Test\Unit
{
    /**
     * @return array<string, array{0: string, 1: string|array<string, mixed>, 2: bool, 3: string}>
     */
    public static function uriProvider()
    {
        return [
            'no query' => ['https://app.example.com/cb', ['code' => 'a b'], false, 'https://app.example.com/cb?code=a+b'],
            'existing query is kept' => ['https://app.example.com/cb?x=1', 'code=c', false, 'https://app.example.com/cb?x=1&code=c'],
            'trailing ?' => ['https://app.example.com/cb?', 'code=c', false, 'https://app.example.com/cb?code=c'],
            'fragment is removed' => ['https://app.example.com/cb#old', 'code=c', false, 'https://app.example.com/cb?code=c'],
            'query and fragment' => ['https://app.example.com/cb?x=1#old', 'code=c', false, 'https://app.example.com/cb?x=1&code=c'],
            'implicit fragment' => ['https://app.example.com/cb?x=1#old', ['access_token' => 't'], true, 'https://app.example.com/cb?x=1#access_token=t'],
            'loopback with port' => ['http://127.0.0.1:8080/cb', 'code=c', false, 'http://127.0.0.1:8080/cb?code=c'],
            'app scheme' => ['com.example.app:/cb', 'code=c', false, 'com.example.app:/cb?code=c'],
            'no params' => ['https://app.example.com/cb#x', [], false, 'https://app.example.com/cb'],
        ];
    }

    /**
     * @dataProvider uriProvider
     * @param string|array<string, mixed> $params
     */
    public function testWithParams($uri, $params, $fragment, $expected)
    {
        $this->assertSame($expected, Uri::withParams($uri, $params, $fragment));
    }
}
