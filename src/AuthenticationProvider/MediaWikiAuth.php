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

use ConfigException;
use MediaWiki\OAuthClient\Client;
use MediaWiki\OAuthClient\ClientConfig;
use MediaWiki\OAuthClient\Consumer;
use MediaWiki\OAuthClient\Exception;
use MediaWiki\OAuthClient\Token;
use MediaWiki\User\UserIdentity;
use Psr\Log\LoggerInterface;

class MediaWikiAuth extends AuthProvider {

	/**
	 * @var Client
	 */
	private $client;

	/**
	 * @inheritDoc
	 */
	public function __construct(
		string $clientId,
		string $clientSecret,
		?string $authUri,
		?string $redirectUri,
		array $extensionData = []
	) {
		if ( $authUri === null ) {
			$message = wfMessage( 'wsoauth-missing-uri' )->parse();
			throw new ConfigException( $message );
		}

		$conf = new ClientConfig( $authUri );
		$conf->setConsumer( new Consumer( $clientId, $clientSecret ) );
		$conf->setRedirUrl( $conf->endpointURL . "/authenticate&" );

		$client = new Client( $conf );

		if ( $redirectUri !== null ) {
			$client->setCallback( $redirectUri );
		}

		$this->client = $client;
	}

	/**
	 * @inheritDoc
	 */
	public function setLogger( LoggerInterface $logger ) {
		parent::setLogger( $logger );
		$this->client->setLogger( $logger );
	}

	/**
	 * @inheritDoc
	 */
	public function login( ?string &$key, ?string &$secret, ?string &$authUrl ): bool {
		$this->logger->debug( 'In ' . __METHOD__ );
		try {
			list( $authUrl, $token ) = $this->client->initiate();

			$key = $token->key;
			$secret = $token->secret;

			return true;
		} catch ( Exception $e ) {
			$this->logger->debug( 'Failed to get request token', [ $e->getMessage() ] );
			return false;
		}
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
		$this->logger->debug( 'In ' . __METHOD__ );
		if ( !isset( $_GET['oauth_verifier'] ) ) {
			$this->logger->debug( 'No oauth_verifier found in URL.' );
			return false;
		}

		try {
			$request_token = new Token( $key, $secret );
			$access_token = $this->client->complete( $request_token, $_GET['oauth_verifier'] );

			$access_token = new Token( $access_token->key, $access_token->secret );
			$identity = $this->client->identify( $access_token );
			$this->logger->debug( 'Identity', [ $identity ] );

			return [
				"name" => $identity->username
			];
		} catch ( \Exception $e ) {
			$this->logger->debug( 'Failed to get user', [ $e->getMessage() ] );
			return false;
		}
	}

	/**
	 * @inheritDoc
	 */
	public function saveExtraAttributes( int $id ): void {
	}
}
