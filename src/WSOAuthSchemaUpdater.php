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

use DatabaseUpdater;
use MediaWiki\Installer\Hook\LoadExtensionSchemaUpdatesHook;
use MWException;

class WSOAuthSchemaUpdater implements LoadExtensionSchemaUpdatesHook {
	/**
	 * Fired when MediaWiki is updated to allow WSOAuth to register updates for the database schema.
	 *
	 * @param DatabaseUpdater $updater
	 * @throws MWException
	 * @internal
	 */
	public function onLoadExtensionSchemaUpdates( $updater ) {
		$directory = $GLOBALS['wgExtensionDirectory'] . '/WSOAuth/sql';
		$type = $updater->getDB()->getType();

		$files = [
			'wsoauth_multiauth_mappings' => '%s/%s/table_wsoauth_multiauth_mappings.sql'
		];

		foreach ( $files as $name => $path ) {
			$path = sprintf( $path, $directory, $type );

			if ( !file_exists( $path ) ) {
				throw new MWException( "WSOAuth does not support database type `$type`." );
			}

			$updater->addExtensionTable( $name, $path );
		}

		$updater->output( 'Please run the WSOAuth multiauth migration script if you have not done so.' );
	}
}
