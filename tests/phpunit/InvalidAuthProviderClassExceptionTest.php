<?php

/**
 * Class InvalidAuthProviderClassExceptionTest
 *
 * @group Exceptions
 * @covers Exception\InvalidAuthProviderClassException
 */
class InvalidAuthProviderClassExceptionTest extends PHPUnit\Framework\TestCase
{
    protected function setUp() : void
    {
        parent::setUp();
    }

    protected function tearDown() : void
    {
        parent::tearDown();
    }

    public function testIsClassInstanceOfException()
    {
        $this->assertInstanceOf(Exception::class, new Exception\InvalidAuthProviderClassException());
    }
}
