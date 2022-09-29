<?php

/**
 * Copyright 2022 Wikibase Solutions
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

use Wikimedia\Rdbms\IDatabase;
use Wikimedia\Rdbms\IResultWrapper;

/*
 * Load the required class
 */
if ( getenv( 'MW_INSTALL_PATH' ) !== false ) {
	require_once getenv( 'MW_INSTALL_PATH' ) . '/maintenance/Maintenance.php';
} else {
	require_once __DIR__ . '/../../../maintenance/Maintenance.php';
}

/**
 * Class MultiAuthMigrate
 */
class MultiAuthMigrate extends Maintenance {
	/**
	 * @var string The ID of the provider to migrate all existing remote accounts to
	 */
	private $provider;

	/**
	 * @var int The number of users already migrated
	 */
	private $current = 0;

	/**
	 * @var int The total number of users to migrate
	 */
	private $total;

	/**
	 * @var \Wikimedia\Rdbms\DBConnRef
	 */
	private $database;

	/**
	 * MigrateUser constructor.
	 *
	 * @inheritDoc
	 */
	public function __construct() {
		parent::__construct();

		$providerDesc = 'The ID of the provider to migrate all the existing remote accounts to.';
		$this->addOption( 'provider', $providerDesc, true, true );
		$this->requireExtension( 'WSOAuth' );
	}

	/**
	 * @inheritDoc
	 * @throws Exception
	 */
	public function execute() {
		$this->provider = $this->getOption( 'provider' );
		$this->database = wfGetDB( DB_PRIMARY );

		if ( !$this->isProviderValid( $this->provider ) ) {
			$this->fatalError(
				"The specified provider is not configured or does not exist. Please configure it before migrating."
			);
		}

		if ( $this->requiresMigration() ) {
			$this->migrateUsers();
		} else {
			$this->output( "Nothing to migrate.\n" );
		}
	}

	/**
	 * Migrates all users.
	 *
	 * @throws Exception
	 */
	private function migrateUsers() {
		$users = $this->getAllUsers();

		$this->total = $users->numRows();
		$this->current = 0;

		$this->printProgress();

		foreach ( $users as $user ) {
			$user = User::newFromId( $user->wsoauth_user );

			$this->migrateUser( $user );
			$this->current++;
			$this->printProgress();
		}

		$this->output( "\n" );
		$this->output( "\t... done ... \n" );
	}

	/**
	 * Migrates the given user.
	 *
	 * @param User $user The user to migrate
	 * @throws Exception
	 */
	private function migrateUser( User $user ) {
		if ( !$user->isRegistered() ) {
			throw new Exception( 'Cannot migrate anonymous user' );
		}

		$localId = $user->getId();
		$remoteName = $this->getRemoteName( $user );

		$this->database->startAtomic( __METHOD__, IDatabase::ATOMIC_CANCELABLE );

		try {
			// Insert the new mapping
			$this->database->insert( 'wsoauth_multiauth_mappings', [
				'wsoauth_user' => $localId,
				'wsoauth_remote_name' => $remoteName,
				'wsoauth_provider_id' => $this->provider
			] );

			// Delete the old mapping and user, so we don't migrate twice
			if ( $this->database->tableExists( 'wsoauth_mappings' ) ) {
				$this->database->delete( 'wsoauth_mappings', [ 'wsoauth_user' => $localId ] );
			}

			$this->database->delete( 'wsoauth_users', [ 'wsoauth_user' => $localId ] );
		} catch ( Exception $exception ) {
			$this->output( "\n" );
			$this->output( "\t... failure, rolling back most recent migration ...\n" );
			$this->database->cancelAtomic( __METHOD__ );

			throw $exception;
		}

		$this->database->endAtomic( __METHOD__ );
	}

	/**
	 * Returns the remote name of the given user.
	 *
	 * @param User $user
	 * @return string
	 */
	private function getRemoteName( User $user ): string {
		if ( !$this->database->tableExists( 'wsoauth_mappings' ) ) {
			// The user is upgrading from a version before 5.0
			return $user->getName();
		}

		$mappings = $this->database->select(
			'wsoauth_mappings',
			'wsoauth_remote_name',
			[
				'wsoauth_user' => $user->getId()
			]
		);

		if ( $mappings->numRows() === 0 ) {
			// There is no mapping, so the remote name is just the name of the user
			return $user->getName();
		}

		return $mappings->current()->wsoauth_remote_name;
	}

	/**
	 * Returns the IDs of all users that need to be migrated.
	 *
	 * @return IResultWrapper
	 */
	private function getAllUsers(): IResultWrapper {
		return $this->database->select( 'wsoauth_users', 'wsoauth_user' );
	}

	/**
	 * Whether migration is required.
	 *
	 * @return bool
	 */
	private function requiresMigration(): bool {
		return $this->database->tableExists( 'wsoauth_users' );
	}

	/**
	 * Prints the progress.
	 */
	private function printProgress() {
		$this->output(
			"\rMigrating users ... \t {$this->getProgress()}% ({$this->current}/{$this->total})"
		);
	}

	/**
	 * Calculates the progress.
	 *
	 * @return string
	 */
	private function getProgress(): string {
		return (string)( $this->total === 0 ? 100 : floor( ( $this->current / $this->total ) * 100 ) );
	}

	/**
	 * Returns true if and only if the given provider is configured.
	 *
	 * @param string $provider
	 * @return bool
	 */
	private function isProviderValid( string $provider ): bool {
		$pluggableAuthConfig = $GLOBALS['wgPluggableAuth_Config'] ?? [];

		return isset( $pluggableAuthConfig[$provider] );
	}
}

$maintClass = MultiAuthMigrate::class;
require_once RUN_MAINTENANCE_IF_MAIN;
