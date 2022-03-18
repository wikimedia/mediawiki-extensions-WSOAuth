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

namespace WSOAuth;

use ConfigException;
use DBError;
use Exception;
use Hooks;
use MediaWiki\Extension\PluggableAuth\PluggableAuth;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserNameUtils;
use RequestContext;
use User;
use WSOAuth\AuthenticationProvider\AuthProvider;
use WSOAuth\AuthenticationProvider\FacebookAuth;
use WSOAuth\AuthenticationProvider\MediaWikiAuth;
use WSOAuth\Exception\ContinuationException;
use WSOAuth\Exception\InitialisationException;
use WSOAuth\Exception\InvalidAuthProviderClassException;
use WSOAuth\Exception\UnknownAuthProviderException;

/**
 * This class implements a 3-legged OAuth login for PluggableAuth.
 *
 * @link https://datatracker.ietf.org/doc/html/rfc6749
 */
class WSOAuth extends PluggableAuth {
	use SessionAwareTrait;

	public const MAPPING_TABLE_NAME = 'wsoauth_multiauth_mappings';
	public const DEFAULT_AUTH_PROVIDERS = [
		"mediawiki" => MediaWikiAuth::class,
		"facebook" => FacebookAuth::class
	];

	/**
	 * @var AuthProvider|null The requested authentication provider
	 */
	private $authProvider;

	/**
	 * @var UserNameUtils The UserNameUtils service
	 */
	private $userNameUtils;

	/**
	 * WSOAuth constructor.
	 *
	 * @param UserNameUtils $userNameUtils
	 */
	public function __construct( UserNameUtils $userNameUtils ) {
		$this->userNameUtils = $userNameUtils;
	}

	/**
	 * @inheritDoc
	 * @throws UnknownAuthProviderException|InvalidAuthProviderClassException|ConfigException
	 */
	public function init( string $configId, ?array $data ) {
		parent::init( $configId, $data );

		if ( !isset( $data['type'] ) ) {
			throw new ConfigException( wfMessage( "wsoauth-not-configured-message" )->parse() );
		}

		$this->authProvider = self::getAuthProvider( $data['type'], $data );
	}

	/**
	 * @param int|null &$id
	 * @param string|null &$username
	 * @param string|null &$realname
	 * @param string|null &$email
	 * @param string|null &$errorMessage
	 * @return bool
	 * @throws Exception
	 * @internal
	 */
	public function authenticate(
		?int &$id,
		?string &$username,
		?string &$realname,
		?string &$email,
		?string &$errorMessage
	): bool {
		try {
			if ( !$this->isContinuation() ) {
				// Initiate the OAuth login, first part of the 3-legged OAuth login
				// Will redirect the user and exit the script if no error occurs
				$this->initiateLogin();
			} else {
				// Continue the OAuth login, last part of the 3-logged OAuth login
				$this->continueLogin(
					$this->popSessionVariable( "request_key" ),
					$this->popSessionVariable( "request_secret" ),
					$id,
					$username,
					$realname,
					$email
				);
			}

			return true;
		} catch ( InitialisationException | ContinuationException $exception ) {
			// Set the error message if something went wrong
			$errorMessage = $exception->getMessage();

			return false;
		}
	}

	/**
	 * @param User &$user
	 * @return void
	 * @throws Exception
	 * @internal
	 */
	public function deauthenticate( UserIdentity &$user ): void {
		Hooks::run( 'WSOAuthBeforeLogout', [ &$user ] );
		$this->authProvider->logout( $user );
	}

	/**
	 * @param int $id
	 * @return void
	 * @throws DBError
	 * @internal
	 */
	public function saveExtraAttributes( int $id ): void {
		$this->createMapping( $id, User::newFromId( $id )->getName() );
		$this->authProvider->saveExtraAttributes( $id );
	}

	/**
	 * First part of 3-legged OAuth login. In this part we retrieve the request token and redirect the user to the
	 * authentication provider.
	 *
	 * @throws InitialisationException
	 */
	private function initiateLogin(): void {
		$result = $this->authProvider->login( $key, $secret, $auth_url );

		if ( $result === false || empty( $auth_url ) ) {
			throw new InitialisationException( wfMessage( 'wsoauth-initiate-login-failure' )->parse() );
		}

		$this->setSessionVariable( 'request_key', $key ?? '' );
		$this->setSessionVariable( 'request_secret', $secret ?? '' );
		$this->saveSession();

		// Redirect the user to the second part of the 3-legged OAuth login
		header( "Location: $auth_url" );
		exit();
	}

	/**
	 * Last part of 3-legged OAuth. Returns true if the login succeeded, false otherwise.
	 *
	 * @param string $key The request key generated by the OAuth provider in the first part
	 * @param string $secret The request secret generated by the OAuth provider in the first part
	 * @param int|null &$id Set this to the user ID (or NULL to create the user)
	 * @param string|null &$username Set this to the username
	 * @param string|null &$realname Set this to the user's real name, or leave empty
	 * @param string|null &$email Set this to the user's email address, or leave empty
	 *
	 * @throws ContinuationException
	 */
	private function continueLogin(
		string $key,
		string $secret,
		?int &$id,
		?string &$username,
		?string &$realname,
		?string &$email
	): void {
		$remoteUserInfo = $this->authProvider->getUser( $key, $secret, $errorMessage );
		$hookResult = Hooks::run( 'WSOAuthAfterGetUser', [ &$remoteUserInfo, &$errorMessage, $this->configId ] );

		if ( $remoteUserInfo === false || $hookResult === false ) {
			// Request failed or user is not authorised
			throw new ContinuationException(
				$errorMessage ?? wfMessage( 'wsoauth-authentication-failure' )->parse()
			);
		}

		if ( !isset( $remoteUserInfo['name'] ) || !$this->userNameUtils->isValid( $remoteUserInfo['name'] ) ) {
			// Missing or invalid 'name' attribute
			throw new ContinuationException( wfMessage( 'wsoauth-invalid-username' )->parse() );
		}

		// Already set the "realname" and "email", so we do not need to worry about that later
		$realname = $remoteUserInfo['realname'] ?? '';
		$email = $remoteUserInfo['email'] ?? '';

		$remoteUsername = ucfirst( $remoteUserInfo['name'] );
		$currentUser = RequestContext::getMain()->getUser();
		$localAccountID = $this->getLocalAccountID( $remoteUsername );

		if ( $localAccountID !== 0 ) {
			// Case 1: A mapping is available from the remote user to a user on the wiki. In this case, we can simply
			// log into the account that has been coupled.
			$username = User::newFromId( $localAccountID )->getName();
			$id = $localAccountID;
		} elseif ( $currentUser->getId() > 0 ) {
			// Case 2: A user is currently logged in locally, and no mapping is available
			// In this case, we want to create a mapping from the remote account to this account.
			$currentUserId = $currentUser->getId();

			$this->createMapping( $currentUserId, $remoteUsername );

			// Log the account in like normal
			$username = $currentUser->getName();
			$id = $currentUserId;
		} else {
			// Case 3: No user is currently logged in locally, and no mapping is available. In this case, we want to
			// create a new account, or usurp an existing account if enabled
			if ( $GLOBALS['wgOAuthDisallowRemoteOnlyAccounts'] === true ) {
				// Block the login, since account creation though remote login is disabled
				throw new ContinuationException( wfMessage( "wsoauth-remote-only-accounts-disabled" )->parse() );
			}

			// Get the user ID of any account with the same name
			$userId = User::newFromName( $remoteUsername )->idForName();

			if ( $userId > 0 ) {
				if ( $GLOBALS['wgOAuthMigrateUsersByUsername'] !== true ) {
					// Automatic remote-only account usurpation is disabled
					throw new ContinuationException(
						wfMessage( 'wsoauth-user-already-exists-message', $remoteUsername )->parse()
					);
				}

				// Usurp the account
				$this->saveExtraAttributes( $userId );
			}

			$username = $remoteUsername;
			$id = $userId > 0 ? $userId : null;
		}
	}

	/**
	 * Creates a mapping from the given remote user name to the given local user ID.
	 *
	 * @param int $localUserID
	 * @param string $remoteAccountName
	 */
	private function createMapping( int $localUserID, string $remoteAccountName ): void {
		wfGetDB( DB_PRIMARY )->insert(
			self::MAPPING_TABLE_NAME,
			[
				'wsoauth_user' => $localUserID,
				'wsoauth_remote_name' => $remoteAccountName,
				'wsoauth_provider_id' => $this->configId
			],
			__METHOD__
		);
	}

	/**
	 * Returns the ID of the local account or null if the user has no mapping.
	 *
	 * @param string $name
	 * @return int The account ID, or 0 is no mapping exists
	 */
	private function getLocalAccountID( string $name ): int {
		$results = wfGetDB( DB_PRIMARY )->select(
			self::MAPPING_TABLE_NAME,
			[ 'wsoauth_user' ],
			[ 'wsoauth_remote_name' => $name, 'wsoauth_provider_id' => $this->configId ],
			__METHOD__
		);

		if ( $results->numRows() === 0 ) {
			return 0;
		}

		return $results->current()->wsoauth_user;
	}

	/**
	 * Returns true if and only if this call to Special:PluggableAuthLogin is a continuation of an initialised login
	 * attempt.
	 *
	 * @return bool
	 */
	private function isContinuation(): bool {
		return $this->doesSessionVariableExist( "request_key" ) &&
			$this->doesSessionVariableExist( "request_secret" );
	}

	/**
	 * Returns the list of available auth providers.
	 *
	 * @return array
	 */
	public static function getAuthProviders(): array {
		$auth_providers = self::DEFAULT_AUTH_PROVIDERS;

		try {
			Hooks::run( "WSOAuthGetAuthProviders", [ &$auth_providers ] );
		} catch ( Exception $exception ) {
		}

		return array_merge( $auth_providers, (array)$GLOBALS['wgOAuthCustomAuthProviders'] );
	}

	/**
	 * Returns an instance of the configured auth provider.
	 *
	 * @param string $type The auth provider type to return (i.e. "mediawiki", "facebook" or a custom provider)
	 * @param array $data The configuration options passed for this authentication provider
	 * @return AuthProvider
	 *
	 * @throws UnknownAuthProviderException|InvalidAuthProviderClassException|ConfigException
	 */
	private static function getAuthProvider( string $type, array $data ): AuthProvider {
		$auth_providers = self::getAuthProviders();

		if ( !isset( $auth_providers[$type] ) ) {
			$message = wfMessage( 'wsoauth-unknown-auth-provider-exception-message' )->params( $type )->parse();
			throw new UnknownAuthProviderException( $message );
		}

		if ( !class_exists( $auth_providers[$type] ) ) {
			$message = wfMessage( 'wsoauth-unknown-auth-provider-class-exception-message' )->parse();
			throw new InvalidAuthProviderClassException( $message );
		}

		if ( !isset( $data['clientId'] ) ) {
			$message = wfMessage( 'wsoauth-missing-client-id' )->parse();
			throw new ConfigException( $message );
		}

		if ( !isset( $data['clientSecret'] ) ) {
			$message = wfMessage( 'wsoauth-missing-client-secret' )->parse();
			throw new ConfigException( $message );
		}

		return new $auth_providers[$type](
			$data['clientId'],
			$data['clientSecret'],
			$data['uri'] ?? null,
			$data['redirectUri'] ?? null
		);
	}
}
