<?php

/**
 * Class UnknownAuthProviderExceptionTest
 *
 * @group Exceptions
 * @covers Exception\UnknownAuthProviderException
 */
class UnknownAuthProviderExceptionTest extends PHPUnit\Framework\TestCase
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
        $this->assertInstanceOf(Exception::class, new Exception\UnknownAuthProviderException());
    }
}
