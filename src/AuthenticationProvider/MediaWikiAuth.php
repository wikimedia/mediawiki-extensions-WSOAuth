<?php

/**
 * Copyright 2020 Marijn van Wezel
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace AuthenticationProvider;

/**
 * Class MediaWikiAuth
 * @package AuthenticationProvider
 */
class MediaWikiAuth implements \AuthProvider {
	/**
	 * @var \MediaWiki\OAuthClient\Client
	 */
	private $client;

	public function __construct() {
		$this->client = self::createClient();
	}

	/**
	 * Log in the user through the external OAuth provider.
	 *
	 * @param string &$key
	 * @param string &$secret
	 * @param string &$auth_url
	 * @return bool Returns true on successful login, false otherwise.
	 * @internal
	 */
	public function login( &$key, &$secret, &$auth_url ) {
		try {
			list( $auth_url, $token ) = $this->client->initiate();

			$key = $token->key;
			$secret = $token->secret;

			return true;
		} catch ( \MediaWiki\OAuthClient\Exception $e ) {
			wfDebugLog( "WSOAuth", $e->getMessage() );
			return false;
		}
	}

	/**
	 * Log out the user and destroy the session.
	 *
	 * @param \User &$user The currently logged in user (i.e. the user that will be logged out).
	 * @return void
	 * @internal
	 */
	public function logout( \User &$user ) {
	}

	/**
	 * Get user info from session. Returns false when the request failed or the user is not authorised.
	 *
	 * @param string $key
	 * @param string $secret
	 * @param string &$errorMessage Message shown to the user when there is an error.
	 * @return bool|array Returns an array with at least a 'name' when the user is authenticated, returns false when the user is not authorised or the authentication failed.
	 * @internal
	 */
	public function getUser( $key, $secret, &$errorMessage ) {
		if ( !isset( $_GET['oauth_verifier'] ) ) {
			return false;
		}

		try {
			$request_token = new \MediaWiki\OAuthClient\Token( $key, $secret );
			$access_token = $this->client->complete( $request_token, $_GET['oauth_verifier'] );

			$access_token = new \MediaWiki\OAuthClient\Token( $access_token->key, $access_token->secret );
			$identity = $this->client->identify( $access_token );

			return [
				"name" => $identity->username
			];
		} catch ( \Exception $e ) {
			return false;
		}
	}

	/**
	 * Gets called whenever a user is successfully authenticated, so extra attributes about the user can be saved.
	 *
	 * @param int $id The ID of the User.
	 * @return void
	 * @internal
	 */
	public function saveExtraAttributes( $id ) {
	}

	/**
	 * @return \MediaWiki\OAuthClient\Client
	 */
	public static function createClient() {
		$conf = new \MediaWiki\OAuthClient\ClientConfig( $GLOBALS['wgOAuthUri'] );
		$conf->setConsumer(
			new \MediaWiki\OAuthClient\Consumer(
				$GLOBALS['wgOAuthClientId'],
				$GLOBALS['wgOAuthClientSecret']
			)
		);
		$conf->setRedirUrl( $conf->endpointURL . "/authenticate&" );

		$client = new \MediaWiki\OAuthClient\Client( $conf );

		$callback = $GLOBALS['wgOAuthRedirectUri'];
		if ( $callback ) {
			$client->setCallback( $callback );
		}

		return $client;
	}
}
