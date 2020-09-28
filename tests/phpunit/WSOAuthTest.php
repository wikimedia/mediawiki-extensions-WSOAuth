<?php

/**
 * Class WSOAuthTest
 *
 * @group WSOAuthCore
 * @covers WSOAuth
 */
class WSOAuthTest extends PHPUnit\Framework\TestCase
{
    protected function setUp() : void
    {
        parent::setUp();
    }

    protected function tearDown() : void
    {
        parent::tearDown();
    }

    /**
     * Tests whether the default authentication provider is an instance of AuthProvider.
     *
     * @throws Exception\UnknownAuthProviderException
     * @throws Exception\InvalidAuthProviderClassException
     */
    public function testAuthenticationProviderIsInstanceOfAuthProvider()
    {
        $this->assertInstanceOf(AuthProvider::class, WSOAuth::getAuthProvider());
    }

    public function testHasMethodAuthenticate()
    {
        $this->assertTrue(method_exists(WSOAuth::class, 'authenticate'));
    }

    public function testHasMethodDeauthenticate()
    {
        $this->assertTrue(method_exists(WSOAuth::class, 'deauthenticate'));
    }

    public function testHasMethodSaveExtraAttributes()
    {
        $this->assertTrue(method_exists(WSOAuth::class, 'saveExtraAttributes'));
    }

    public function testExtendsPluggableAuth()
    {
        $this->assertTrue(is_subclass_of(WSOAuth::class, 'PluggableAuth'));
    }
}
