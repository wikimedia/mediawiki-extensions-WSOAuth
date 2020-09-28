<?php

require_once "IAuthProvider.php";

/**
 * Class MediaWikiAuthTest
 *
 * @group AuthProviders
 * @covers AuthenticationProvider\MediaWikiAuth
 */
class MediaWikiAuthTest extends PHPUnit\Framework\TestCase implements IAuthProvider
{
    protected function setUp() : void
    {
        parent::setUp();
    }

    protected function tearDown() : void
    {
        parent::tearDown();
    }

    public function testIsClientInstanceOfMediaWikiOAuthClientClient()
    {
        $this->assertInstanceOf(MediaWiki\OAuthClient\Client::class, AuthenticationProvider\MediaWikiAuth::createClient());
    }

    public function testIsClassInstanceOfAuthProvider()
    {
        $this->assertTrue(
            in_array("AuthProvider", class_implements(AuthenticationProvider\MediaWikiAuth::class)),
            "Class does not implement interface AuthProvider"
        );
    }
}
