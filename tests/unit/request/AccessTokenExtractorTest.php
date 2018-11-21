<?php

namespace tests\unit\request;

use conquer\oauth2\Exception;
use conquer\oauth2\request\AccessTokenExtractor;
use yii\web\HeaderCollection;
use yii\web\Request;

class AccessTokenExtractorTest extends \Codeception\Test\Unit
{
    /**
     * @test
     */
    public function exceptionWhenNoAccessTokenIsPresent()
    {
        $this->expectException(Exception::class);
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getHeaders' => new HeaderCollection,
        ]));
        $extractor->extract();
    }

    /**
     * @test
     */
    public function exceptionWhenMultipleAccessTokensArePresent()
    {
        $this->expectException(Exception::class);
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getHeaders' => (new HeaderCollection)->add('Authorization', 'Bearer 123'),
            'getQueryParams' => ['access_token' => '321'],
        ]));
        $extractor->extract();
    }

    /**
     * @test
     */
    public function exceptionWhenAccessTokenInBodyOfNonPostRequest()
    {
        $this->expectException(Exception::class);
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getBodyParams' => ['access_token' => '321'],
            'getMethod' => 'PATCH',
        ]));
        $extractor->extract();
    }

    /**
     * @test
     */
    public function exceptionWhenWrongContentTypeInRequest()
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
     * @test
     */
    public function postAccessTokenIsReturned()
    {
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getBodyParams' => ['access_token' => '321'],
            'getMethod' => 'POST',
            'getContentType' => 'application/x-www-form-urlencoded',

        ]));
        $this->assertEquals('321', $extractor->extract());
    }

    /**
     * @test
     */
    public function getAccessTokenIsReturned()
    {
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getQueryParams' => ['access_token' => '321'],
            'getMethod' => 'GET',
        ]));
        $this->assertEquals('321', $extractor->extract());
    }

    /**
     * @test
     */
    public function headerAccessTokenIsReturned()
    {
        $extractor = new AccessTokenExtractor($this->make(Request::class, [
            'getHeaders' => (new HeaderCollection)->add('Authorization', 'Bearer 321'),
            'getMethod' => 'GET',
        ]));
        $this->assertEquals('321', $extractor->extract());
    }

    /**
     * @test
     */
    public function headerAccessTokenIsReturnedWithOtherAuthHeaders()
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