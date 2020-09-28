<?php

/**
 * Class AuthProviderTest
 *
 * @group AuthProvider
 * @covers AuthProvider
 */
class AuthProviderTest extends PHPUnit\Framework\TestCase
{
    protected function setUp() : void
    {
        parent::setUp();
    }

    protected function tearDown() : void
    {
        parent::tearDown();
    }

    public function testHasInterfaceLoginMethod()
    {
        $this->assertTrue(
            method_exists(AuthProvider::class, 'login'),
            "Interface does not have method login"
        );
    }

    public function testHasInterfaceLogoutMethod()
    {
        $this->assertTrue(
            method_exists(AuthProvider::class, 'logout'),
            "Interface does not have method logout"
        );
    }

    public function testHasInterfaceGetUserMethod()
    {
        $this->assertTrue(
            method_exists(AuthProvider::class, 'getUser'),
            "Interface does not have method getUser"
        );
    }

    public function testHasInterfaceSaveExtraAttributesMethod()
    {
        $this->assertTrue(
            method_exists(AuthProvider::class, 'saveExtraAttributes'),
            "Interface does not have method saveExtraAttributes"
        );
    }
}
