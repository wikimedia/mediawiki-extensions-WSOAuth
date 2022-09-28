<?php

/**
 * Copyright 2020 Marijn van Wezel
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
 * LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace WSOAuth\AuthenticationProvider;

use League\OAuth2\Client\Provider\Facebook;
use MediaWiki\User\UserIdentity;

class FacebookAuth extends AuthProvider {

	/**
	 * @var Facebook
	 */
	private $provider;

	/**
	 * @inheritDoc
	 */
	public function __construct( string $clientId, string $clientSecret, ?string $authUri, ?string $redirectUri ) {
		$this->provider = new Facebook( [
			'clientId' => $clientId,
			'clientSecret' => $clientSecret,
			'redirectUri' => $redirectUri,
			'graphApiVersion' => 'v6.0'
		] );
	}

	/**
	 * @inheritDoc
	 */
	public function login( ?string &$key, ?string &$secret, ?string &$authUrl ): bool {
		$authUrl = $this->provider->getAuthorizationUrl( [
			'scope' => [ 'email' ]
		] );

		$secret = $this->provider->getState();

		return true;
	}

	/**
	 * @inheritDoc
	 */
	public function logout( UserIdentity &$user ): void {
	}

	/**
	 * @inheritDoc
	 */
	public function getUser( string $key, string $secret, &$errorMessage ) {
		if ( !isset( $_GET['code'] ) ) {
			return false;
		}

		if ( !isset( $_GET['state'] ) || empty( $_GET['state'] ) || ( $_GET['state'] !== $secret ) ) {
			return false;
		}

		try {
			$token = $this->provider->getAccessToken( 'authorization_code', [ 'code' => $_GET['code'] ] );
			$user = $this->provider->getResourceOwner( $token );

			return [
				'name' => $user->getId(),
				'realname' => $user->getName(),
				'email' => $user->getEmail()
			];
		} catch ( \Exception $e ) {
			return false;
		}
	}

	/**
	 * @inheritDoc
	 */
	public function saveExtraAttributes( int $id ): void {
	}
}
