<?php

namespace tests\unit\request;

use conquer\oauth2\Exception;
use conquer\oauth2\request\AccessTokenExtractor;
use yii\web\HeaderCollection;
use yii\web\Request;

class AccessTokenExtractorTest extends \Codeception\Test\Unit
{
    /**
     * @return void
     */
    public function testExceptionWhenNoAccessTokenIsPresent()
    {
        $this->expectException(Exception::class);
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getHeaders' => new HeaderCollection,
        ]));
        $extractor->extract();
    }

    /**
     * @return void
     */
    public function testExceptionWhenMultipleAccessTokensArePresent()
    {
        $this->expectException(Exception::class);
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getHeaders' => (new HeaderCollection)->add('Authorization', 'Bearer 123'),
            'getQueryParams' => ['access_token' => '321'],
        ]));
        $extractor->extract();
    }

    /**
     * @return void
     */
    public function testExceptionWhenAccessTokenInBodyOfNonPostRequest()
    {
        $this->expectException(Exception::class);
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getBodyParams' => ['access_token' => '321'],
            'getMethod' => 'PATCH',
        ]));
        $extractor->extract();
    }

    /**
     * @return void
     */
    public function testExceptionWhenWrongContentTypeInRequest()
    {
        $this->expectException(Exception::class);
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getBodyParams' => ['access_token' => '321'],
            'getMethod' => 'POST',
            'getContentType' => 'application/json',
        ]));
        $extractor->extract();
    }

    /**
     * @return void
     */
    public function testPostAccessTokenIsReturned()
    {
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getBodyParams' => ['access_token' => '321'],
            'getMethod' => 'POST',
            'getContentType' => 'application/x-www-form-urlencoded',

        ]));
        $this->assertEquals('321', $extractor->extract());
    }

    /**
     * @return void
     */
    public function testGetAccessTokenIsReturned()
    {
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getQueryParams' => ['access_token' => '321'],
            'getMethod' => 'GET',
        ]));
        $this->assertEquals('321', $extractor->extract());
    }

    /**
     * @return void
     */
    public function testHeaderAccessTokenIsReturned()
    {
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getHeaders' => (new HeaderCollection)->add('Authorization', 'Bearer 321'),
            'getMethod' => 'GET',
        ]));
        $this->assertEquals('321', $extractor->extract());
    }

    /**
     * @return void
     */
    public function testHeaderAccessTokenIsReturnedWithOtherAuthHeaders()
    {
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getHeaders' => (new HeaderCollection)
                ->add('Authorization', 'Basic 111')
                ->add('Authorization', 'Bearer 222')
                ->add('Custom', 'Header')
                ->add('Authorization', 'Advanced 333'),
            'getMethod' => 'GET',
        ]));
        $this->assertEquals('222', $extractor->extract());
    }
}