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

use AuthenticationProvider\FacebookAuth;
use AuthenticationProvider\MediaWikiAuth;
use Exception\InvalidAuthProviderClassException;
use Exception\UnknownAuthProviderException;
use MediaWiki\MediaWikiServices;
use OOUI\ButtonWidget;

/**
 * Class WSOAuth
 */
class WSOAuth extends AuthProviderFramework {
	const DEFAULT_AUTH_PROVIDERS = [
		"mediawiki" => MediaWikiAuth::class,
		"facebook" => FacebookAuth::class
	];

	/**
	 * @var AuthProvider
	 */
	private $auth_provider;

	/**
	 * WSOAuth constructor.
	 * @throws FatalError
	 * @throws InvalidAuthProviderClassException
	 * @throws MWException
	 * @throws UnknownAuthProviderException
	 * @internal
	 */
	public function __construct() {
		parent::__construct();

		if ( $GLOBALS['wgOAuthUri'] !== false && $GLOBALS['wgOAuthClientId'] !== false && $GLOBALS['wgOAuthClientSecret'] !== false ) {
			$this->auth_provider = self::getAuthProvider();
		}
	}

	/**
	 * @param int &$id
	 * @param string &$username
	 * @param string &$realname
	 * @param string &$email
	 * @param string &$errorMessage
	 * @return bool
	 * @throws FatalError
	 * @throws MWException
	 * @internal
	 */
	public function authenticate( &$id, &$username, &$realname, &$email, &$errorMessage ) {
		if ( !isset( $this->auth_provider ) ) {
			$errorMessage = wfMessage( "wsoauth-not-configured-message" )->parse();
			return false;
		}

		if ( $this->doesSessionVariableExist( "request_key" ) && $this->doesSessionVariableExist( "request_secret" ) ) {
			$key = $this->getSessionVariable( "request_key" );
			$secret = $this->getSessionVariable( "request_secret" );

			$this->removeSessionVariable( "request_key" );
			$this->removeSessionVariable( "request_secret" );

			$user_info = $this->auth_provider->getUser( $key, $secret, $errorMessage );
			$hook = Hooks::run( 'WSOAuthAfterGetUser', [ &$user_info, &$errorMessage ] );

			// Request failed or user is not authorised.
			if ( $user_info === false || $hook === false ) {
				$errorMessage = !empty( $errorMessage ) ? $errorMessage : wfMessage( 'wsoauth-authentication-failure' )->parse();
				return false;
			}

			if ( !isset( $user_info['name'] ) ) {
				$errorMessage = wfMessage( 'wsoauth-invalid-username' )->parse();
				return false;
			}

			$services = MediaWikiServices::getInstance();
			if ( method_exists( $services, 'getUserNameUtils' ) ) {
				// MW 1.35 +
				$isValidUsername = $services->getUserNameUtils()->isValid( $user_info['name'] );
			} else {
				$isValidUsername = User::isValidUserName( $user_info['name'] );
			}
			if ( !$isValidUsername ) {
				$errorMessage = wfMessage( 'wsoauth-invalid-username' )->parse();
				return false;
			}

			// Already set the "realname" and "email", so we do not need to worry about that later
			$realname = isset( $user_info['realname'] ) ? $user_info['realname'] : '';
			$email = isset( $user_info['email'] ) ? $user_info['email'] : '';

			$remote_user_name = ucfirst( $user_info['name'] );

			$current_user = RequestContext::getMain()->getUser();
			$mapped_local_id = $this->getLocalAccountID( $user_info['name'] );

			if ( $mapped_local_id !== false && $current_user->isAnon() ) {
				// Case 1: No user is currently logged in locally, and a mapping is available from the remote
				// user to a user on the wiki
				$remote_user_object = User::newFromId( $mapped_local_id );

				// Set the required "username" and "id" attributes for PluggableAuth
				$username = $remote_user_object->getName();
				$id = $mapped_local_id;

				// Tell PluggableAuth the login succeeded
				return true;
			} elseif ( $mapped_local_id !== false && !$current_user->isAnon() ) {
				// Case 2: A user is currently logged in locally, and a mapping is available from the remote
				// user to a user on the wiki, and that mapping is not
				$errorMessage = wfMessage( "wsoauth-remote-already-used", $remote_user_name )->parse();

				// Tell PluggableAuth the login failed
				return false;
			} elseif ( $mapped_local_id === false && $current_user->isAnon() ) {
				// Case 3: No user is currently logged in locally, and no mapping is available
				if ( $GLOBALS['wgOAuthDisallowRemoteOnlyAccounts'] === true ) {
					// Block the login, since remote-only accounts are disabled
					$errorMessage = wfMessage( "wsoauth-remote-only-accounts-disabled" )->parse();

					// Tell PluggableAuth the login failed
					return false;
				}

				// Regular account usurpation should be used

				$user = User::newFromName( $remote_user_name );
				$user_id = $user->idForName();

				if ( !$this->userLoggedInThroughOAuth( $user_id ) ) {
					// The user has not logged in through OAuth before

					if ( $GLOBALS['wgOAuthMigrateUsersByUsername'] === false ) {
						// Automatic remote-only account usurpation is disabled

						$errorMessage = wfMessage(
							'wsoauth-user-already-exists-message',
							$remote_user_name
						)->parse();

						// Tell PluggableAuth the login failed
						return false;
					}

					// Usurp the account
					$this->saveExtraAttributes( $user_id );
				}

				// Set the required "username" and "id" attributes for PluggableAuth
				$username = $remote_user_name;
				$id = $user_id === 0 ? null : $user_id;

				// Tell PluggableAuth the login succeeded
				return true;
			} elseif ( $mapped_local_id === false && !$current_user->isAnon() ) {
				// Case 4: A user is currently logged in locally, and no mapping is available

				$current_user_id = $current_user->getId();

				if ( $this->getMappedAccountName( $current_user_id ) !== false ) {
					// The user already has a different remote account coupled
					$errorMessage = wfMessage( "wsoauth-account-already-coupled" )->parse();

					// Tell PluggableAuth the login failed
					return false;
				}

				if ( $this->userLoggedInThroughOAuth( $current_user_id ) ) {
					// The current user has already logged in through OAuth
					$errorMessage = wfMessage( "wsoauth-already-logged-in-through-remote" )->parse();

					// Tell PluggableAuth the login failed
					return false;
				}

				// A mapping should be created. Please note that if the remote account name and the local account
				// name are the same, a mapping is not really needed, but we still create one for simplicity.

				// If we reach this code, it means that no mapping exists from the remote account name to a local
				// user ID (or the other way around), and a user is currently logged in that is trying to usurp
				// the remote account

				// Usurp the account like normal
				$this->saveExtraAttributes( $current_user_id );

				// Create a mapping so WSOAuth knows that this remote belongs to the currently logged-in user
				$this->createMapping( $current_user_id, $remote_user_name );

				// Log the account in like normal
				$username = $current_user->getName();
				$id = $current_user_id;

				// Tell PluggableAuth the login succeeded
				return true;
			}

			// All cases should be covered here, but to be save, return false
			$errorMessage = wfMessage( "wsoauth-authentication-failure" )->parse();
			return false;
		}

		$result = $this->auth_provider->login( $key, $secret, $auth_url );

		if ( $result === false || empty( $auth_url ) ) {
			$errorMessage = wfMessage( 'wsoauth-initiate-login-failure' )->parse();
			return false;
		}

		$this->setSessionVariable( 'request_key', $key );
		$this->setSessionVariable( 'request_secret', $secret );
		$this->saveSession();

		header( "Location: $auth_url" );

		exit;
	}

	/**
	 * @param User &$user
	 * @return void
	 * @throws Exception
	 * @internal
	 */
	public function deauthenticate( User &$user ) {
		Hooks::run( 'WSOAuthBeforeLogout', [ &$user ] );

		$this->auth_provider->logout( $user );
	}

	/**
	 * @param int $id
	 * @return void
	 * @throws DBError
	 * @internal
	 */
	public function saveExtraAttributes( $id ) {
		$dbr = wfGetDB( DB_MASTER );
		$dbr->insert( 'wsoauth_users', [ 'wsoauth_user' => $id ] );

		$this->auth_provider->saveExtraAttributes( $id );
	}

	/**
	 * Creates a mapping from the given remote user name to the given local user ID.
	 *
	 * @param int $current_user_id
	 * @param string $remote_user_name
	 */
	private function createMapping( $current_user_id, $remote_user_name ) {
		$dbr = wfGetDB( DB_MASTER );
		$dbr->insert(
			'wsoauth_mappings',
			[
				'wsoauth_user' => $current_user_id,
				'wsoauth_remote_name' => $remote_user_name
			],
			__METHOD__
		);
	}

	/**
	 * Returns an instance of the configured auth provider.
	 *
	 * @return AuthProvider
	 * @throws InvalidAuthProviderClassException
	 * @throws UnknownAuthProviderException
	 * @internal
	 */
	public static function getAuthProvider() {
		$auth_providers = array_merge( self::getAuthProviders(), (array)$GLOBALS['wgOAuthCustomAuthProviders'] );
		$auth_provider = $GLOBALS['wgOAuthAuthProvider'];

		if ( !isset( $auth_providers[$auth_provider] ) ) {
			throw new Exception\UnknownAuthProviderException( wfMessage( 'wsoauth-unknown-auth-provider-exception-message' )->params( $auth_provider )->parse() );
		}

		if ( !class_exists( $auth_providers[$auth_provider] ) ) {
			throw new Exception\InvalidAuthProviderClassException( wfMessage( 'wsoauth-unknown-auth-provider-class-exception-message' )->parse() );
		}

		if ( !class_implements( $auth_providers[$auth_provider] ) ) {
			throw new Exception\InvalidAuthProviderClassException( wfMessage( 'wsoauth-invalid-auth-provider-class-exception-message' )->parse() );
		}

		return new $auth_providers[$auth_provider]();
	}

	/**
	 * Returns the list of available auth providers.
	 *
	 * @return array
	 * @throws Exception
	 */
	public static function getAuthProviders() {
		$auth_providers = self::DEFAULT_AUTH_PROVIDERS;
		Hooks::run( "WSOAuthGetAuthProviders", [ &$auth_providers ] );

		return $auth_providers;
	}

	/**
	 * Adds the user to the groups defined via $wgOAuthAutoPopulateGroups after authentication.
	 *
	 * @param User $user
	 * @return bool
	 * @throws Exception
	 * @internal
	 */
	public static function onPluggableAuthPopulateGroups( User $user ) {
		$result = Hooks::run( 'WSOAuthBeforeAutoPopulateGroups', [ &$user ] );

		if ( $result === false ) {
			return false;
		}

		if ( !isset( $GLOBALS['wgOAuthAutoPopulateGroups'] ) ) {
			return false;
		}

		if ( method_exists( MediaWikiServices::class, 'getUserGroupManager' ) ) {
			// MW 1.35+
			$effectiveGroups = MediaWikiServices::getInstance()->getUserGroupManager()
				->getUserEffectiveGroups( $user );
		} else {
			$effectiveGroups = $user->getEffectiveGroups();
		}
		// Subtract the groups the user already has from the list of groups to populate.
		$populate_groups = array_diff( (array)$GLOBALS['wgOAuthAutoPopulateGroups'], $effectiveGroups );

		if ( method_exists( MediaWikiServices::class, 'getUserGroupManager' ) ) {
			// MW 1.35+
			$userGroupManager = MediaWikiServices::getInstance()->getUserGroupManager();
			foreach ( $populate_groups as $populate_group ) {
				$userGroupManager->addUserToGroup( $user, $populate_group );
			}
		} else {
			foreach ( $populate_groups as $populate_group ) {
				$user->addGroup( $populate_group );
			}
		}

		return true;
	}

	/**
	 * Fired when MediaWiki is updated to allow WSOAuth to register updates for the database schema.
	 *
	 * @param DatabaseUpdater $updater
	 * @throws MWException
	 * @internal
	 */
	public static function onLoadExtensionSchemaUpdates( DatabaseUpdater $updater ) {
		$directory = $GLOBALS['wgExtensionDirectory'] . '/WSOAuth/sql';
		$type = $updater->getDB()->getType();

		$wsoauth_users_sql_file = sprintf( "%s/%s/table_wsoauth_users.sql", $directory, $type );
		$wsoauth_mappings_sql_file = sprintf( "%s/%s/table_wsoauth_mappings.sql", $directory, $type );

		if ( !file_exists( $wsoauth_users_sql_file ) || !file_exists( $wsoauth_mappings_sql_file ) ) {
			throw new MWException( "WSOAuth does not support database type `$type`." );
		}

		$updater->addExtensionTable( 'wsoauth_users', $wsoauth_users_sql_file );
		$updater->addExtensionTable( 'wsoauth_mappings', $wsoauth_mappings_sql_file );
	}

	/**
	 * Returns true if and only if the given ID exists in the table `wsoauth_users`.
	 *
	 * @param int $id
	 * @return bool Whether or not this user was registered by WSOAuth.
	 * @throws MWException
	 * @internal
	 */
	public static function userLoggedInThroughOAuth( $id ) {
		if ( !is_int( $id ) ) {
			throw new MWException( "Given user ID is not an integer." );
		}

		$dbr = wfGetDB( DB_REPLICA );
		return $dbr->selectRowCount(
			'wsoauth_users',
			[ 'wsoauth_user' ],
			[ 'wsoauth_user' => $id ],
			__METHOD__
		) === 1;
	}

	/**
	 * Modify user preferences.
	 *
	 * @param User $user
	 * @param array &$preferences
	 * @return bool
	 * @throws MWException
	 */
	public static function onGetPreferences( User $user, &$preferences ) {
		$user_id = $user->getId();

		if ( self::userLoggedInThroughOAuth( $user_id ) ) {
			$remote_account_name = self::getMappedAccountName( $user->getId() ) ?: $user->getName();
			$preferences_default = wfMessage( "wsoauth-remote-connected", $remote_account_name )->parse();
		} else {
			RequestContext::getMain()->getOutput()->enableOOUI();
			$preferences_default = new ButtonWidget( [
				'href' => SpecialPage::getTitleFor( 'WSOAuthConnectRemote' )->getLinkURL(),
				'label' => wfMessage( 'wsoauth-connect-remote' )->plain()
			] );
		}

		$preferences += [ 'wsoauth-prefs-manage-remote' =>
			[
				'section' => 'personal/info',
				'label-message' => 'wsoauth-prefs-manage-remote',
				'type' => 'info',
				'raw' => true,
				'default' => (string)$preferences_default
			],
		];

		return true;
	}

	/**
	 * Returns the ID of the local account or false if the user has no mapping.
	 *
	 * @param string $name
	 * @return int|false
	 * @throws MWException
	 */
	private static function getLocalAccountID( $name ) {
		if ( !is_string( $name ) ) {
			throw new MWException( "Given username is not a string." );
		}

		$dbr = wfGetDB( DB_REPLICA );
		$results = $dbr->select(
			'wsoauth_mappings',
			[ 'wsoauth_user' ],
			[ 'wsoauth_remote_name' => $name ],
			__METHOD__
		);

		if ( $results->numRows() === 0 ) {
			return false;
		}

		return $results->current()->wsoauth_user;
	}

	/**
	 * Returns the name of the remote account or false if the user has no mapping.
	 *
	 * @param int $id
	 * @return string|false
	 * @throws MWException
	 */
	private static function getMappedAccountName( $id ) {
		if ( !is_int( $id ) ) {
			throw new MWException( "Given user ID is not an integer." );
		}

		$dbr = wfGetDB( DB_REPLICA );
		$results = $dbr->select(
			'wsoauth_mappings',
			[ 'wsoauth_remote_name' ],
			[ 'wsoauth_user' => $id ],
			__METHOD__
		);

		if ( $results->numRows() === 0 ) {
			return false;
		}

		return $results->current()->wsoauth_remote_name;
	}
}
