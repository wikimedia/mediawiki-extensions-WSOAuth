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

namespace WSOAuth;

use ConfigException;
use DBError;
use Exception;
use Hooks;
use MediaWiki\Extension\PluggableAuth\PluggableAuth;
use MediaWiki\Session\Session;
use MediaWiki\Session\SessionManager;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserNameUtils;
use RequestContext;
use User;
use WSOAuth\AuthenticationProvider\AuthProvider;
use WSOAuth\AuthenticationProvider\FacebookAuth;
use WSOAuth\AuthenticationProvider\MediaWikiAuth;
use WSOAuth\Exception\ContinuationException;
use WSOAuth\Exception\FinalisationException;
use WSOAuth\Exception\InitialisationException;
use WSOAuth\Exception\InvalidAuthProviderClassException;
use WSOAuth\Exception\UnknownAuthProviderException;

/**
 * This class implements a 3-legged OAuth login for PluggableAuth.
 *
 * @link https://datatracker.ietf.org/doc/html/rfc6749
 */
class WSOAuth extends PluggableAuth {
	public const WSOAUTH_REMOTE_USERNAME_SESSION_KEY = 'WSOAuthRemoteUsername';
	public const WSOAUTH_OAUTH_REQUEST_KEY_SESSION_KEY = 'WSOAuthOAuthRequestKey';
	public const WSOAUTH_OAUTH_REQUEST_SECRET_SESSION_KEY = 'WSOAuthOAuthRequestSecret';

	public const UNIQUE_NAME_MAX_TRIES = 256;
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
	 * @var bool Whether to disallow remote only accounts
	 */
	private $disallowRemoteOnlyAccounts;

	/**
	 * @var bool Whether to use the real name as the username
	 */
	private $useRealNameAsUsername;

	/**
	 * @var bool Whether to migrate users based on their username
	 */
	private $migrateUsersByUsername;

	/**
	 * @var Session The current global session
	 */
	private $session;

	/**
	 * WSOAuth constructor.
	 *
	 * @param UserNameUtils $userNameUtils
	 */
	public function __construct( UserNameUtils $userNameUtils ) {
		$this->userNameUtils = $userNameUtils;
		$this->session = SessionManager::getGlobalSession();
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

		$this->authProvider = $this->getAuthProvider( $data['type'], $data );
		$this->authProvider->setLogger( $this->logger );

		$this->disallowRemoteOnlyAccounts = $this->data['disallowRemoteOnlyAccounts'] ??
			$GLOBALS['wgOAuthDisallowRemoteOnlyAccounts'];

		$this->useRealNameAsUsername = $this->data['useRealNameAsUsername'] ??
			$GLOBALS['wgOAuthUseRealNameAsUsername'];

		$this->migrateUsersByUsername = $this->data['migrateUsersByUsername'] ??
			$GLOBALS['wgOAuthMigrateUsersByUsername'];
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
				$requestKey = $this->session->get( self::WSOAUTH_OAUTH_REQUEST_KEY_SESSION_KEY );
				$requestSecret = $this->session->get( self::WSOAUTH_OAUTH_REQUEST_SECRET_SESSION_KEY );

				try {
					// Continue the OAuth login, last part of the 3-logged OAuth login
					$this->continueLogin(
						$requestKey,
						$requestSecret,
						$id,
						$username,
						$realname,
						$email
					);
				} finally {
					$this->session->remove( self::WSOAUTH_OAUTH_REQUEST_KEY_SESSION_KEY );
					$this->session->remove( self::WSOAUTH_OAUTH_REQUEST_SECRET_SESSION_KEY );
					$this->session->save();
				}
			}

			return true;
		} catch ( InitialisationException | ContinuationException | FinalisationException $exception ) {
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
	 * @throws DBError|FinalisationException
	 * @internal
	 */
	public function saveExtraAttributes( int $id ): void {
		$remoteUsername = $this->session->get( self::WSOAUTH_REMOTE_USERNAME_SESSION_KEY );

		if ( $remoteUsername === null ) {
			throw new FinalisationException( wfMessage( "wsoauth-could-not-create-mapping" )->parse() );
		}

		$this->createMapping( $id, $remoteUsername );
		$this->authProvider->saveExtraAttributes( $id );
	}

	/**
	 * First part of 3-legged OAuth login. In this part we retrieve the request token and redirect the user to the
	 * authentication provider.
	 *
	 * @throws InitialisationException
	 */
	private function initiateLogin(): void {
		$this->logger->debug( 'In ' . __METHOD__ );
		$result = $this->authProvider->login( $key, $secret, $auth_url );

		if ( $result === false || empty( $auth_url ) ) {
			$this->logger->debug( 'Result empty or no auth URL.' );
			throw new InitialisationException( wfMessage( 'wsoauth-initiate-login-failure' )->parse() );
		}

		$this->session->set( self::WSOAUTH_OAUTH_REQUEST_KEY_SESSION_KEY, $key );
		$this->session->set( self::WSOAUTH_OAUTH_REQUEST_SECRET_SESSION_KEY, $secret );
		$this->session->save();

		// Redirect the user to the second part of the 3-legged OAuth login
		header( "Location: $auth_url" );
		exit();
	}

	/**
	 * Last part of 3-legged OAuth. Returns true if the login succeeded, false otherwise.
	 *
	 * @param string|null $key The request key generated by the OAuth provider in the first part
	 * @param string $secret The request secret generated by the OAuth provider in the first part
	 * @param int|null &$id Set this to the user ID (or NULL to create the user)
	 * @param string|null &$username Set this to the username
	 * @param string|null &$realname Set this to the user's real name, or leave empty
	 * @param string|null &$email Set this to the user's email address, or leave empty
	 *
	 * @throws ContinuationException|FinalisationException
	 */
	private function continueLogin(
		?string $key,
		string $secret,
		?int &$id,
		?string &$username,
		?string &$realname,
		?string &$email
	): void {
		$this->logger->debug( 'In ' . __METHOD__ );
		$remoteUserInfo = $this->authProvider->getUser( (string)$key, $secret, $errorMessage );
		$hookResult = Hooks::run( 'WSOAuthAfterGetUser', [ &$remoteUserInfo, &$errorMessage, $this->configId ] );

		if ( $remoteUserInfo === false || $hookResult === false ) {
			$this->logger->debug( 'Request failed or user is not authorised' );
			throw new ContinuationException(
				$errorMessage ?? wfMessage( 'wsoauth-authentication-failure' )->parse()
			);
		}

		if ( !isset( $remoteUserInfo['name'] )
			|| !$this->userNameUtils->isValid( ucfirst( $remoteUserInfo['name'] ) )
		) {
			// Missing or invalid 'name' attribute
			throw new ContinuationException( wfMessage( 'wsoauth-invalid-username' )->parse() );
		}

		// Set $realname and $email to the values returned from the authentication provider, if they are available
		$realname = $remoteUserInfo['realname'] ?? null;
		$email = $remoteUserInfo['email'] ?? null;

		$remoteUsername = ucfirst( $remoteUserInfo['name'] );
		$localUserId = $this->getLocalAccountID( $remoteUsername );

		$this->session->set( self::WSOAUTH_REMOTE_USERNAME_SESSION_KEY, $remoteUsername );
		$this->session->save();

		if ( $localUserId !== 0 ) {
			// Case 1: A mapping is available from the remote user to a user on the wiki. In this case, we can simply
			// log into the account that has been coupled.
			$username = User::newFromId( $localUserId )->getName();
			$id = $localUserId;
		} elseif ( RequestContext::getMain()->getUser()->getId() > 0 ) {
			// Case 2: A user is currently logged in locally, and no mapping is available
			// In this case, we want to create a mapping from the remote account to this account.
			$currentUser = RequestContext::getMain()->getUser();
			$currentUserId = $currentUser->getId();

			$this->createMapping( $currentUserId, $remoteUsername );

			// Log the account in like normal
			$username = $currentUser->getName();
			$id = $currentUserId;
		} else {
			// Case 3: No user is currently logged in locally, and no mapping is available. In this case, we want to
			// create a new account, or usurp an existing account if enabled
			if ( $this->disallowRemoteOnlyAccounts ) {
				// Block the login, since account creation though remote login is disabled
				throw new ContinuationException( wfMessage( "wsoauth-remote-only-accounts-disabled" )->parse() );
			}

			$desiredLocalUsername = $this->useRealNameAsUsername && $realname !== null ? $realname : $remoteUsername;
			$userId = User::newFromName( $desiredLocalUsername )->idForName();

			if ( $userId > 0 && $this->migrateUsersByUsername ) {
				// Usurp the account
				$this->saveExtraAttributes( $userId );

				$username = $desiredLocalUsername;
				$id = $userId;
			} else {
				// Create a new account with a unique name
				$username = $this->getUniqueName( $desiredLocalUsername );
				// We can set $id to null since $username is guaranteed to not exist on the wiki
				$id = null;
			}
		}
	}

	/**
	 * Creates a mapping from the given remote username to the given local user ID.
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
		return $this->session->exists( self::WSOAUTH_OAUTH_REQUEST_KEY_SESSION_KEY ) &&
			$this->session->exists( self::WSOAUTH_OAUTH_REQUEST_SECRET_SESSION_KEY );
	}

	/**
	 * Returns a valid unique name based on the given name. This function checks if the given name is available as a
	 * username on the wiki, if it is, it will return that, otherwise it will continually increment a number and
	 * append that until a username that is available is found.
	 *
	 * @param string $name
	 * @return string
	 * @throws ContinuationException
	 */
	private function getUniqueName( string $name ): string {
		if ( !$this->userNameUtils->isValid( $name ) ) {
			// Missing or invalid 'name' attribute
			throw new ContinuationException( wfMessage( 'wsoauth-invalid-username' )->parse() );
		}

		$name = ucfirst( $name );
		$userId = User::newFromName( $name )->idForName();

		if ( $userId === 0 ) {
			// The real name is not yet taken
			return $name;
		}

		for ( $i = 1; $i < self::UNIQUE_NAME_MAX_TRIES; $i++ ) {
			$newRealname = sprintf( "%s %s", $name, $i );
			$userId = User::newFromName( $newRealname )->idForName();

			if ( $userId === 0 ) {
				return $newRealname;
			}
		}

		throw new ContinuationException( 'Unable to get a unique real name' );
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
	private function getAuthProvider( string $type, array $data ): AuthProvider {
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
