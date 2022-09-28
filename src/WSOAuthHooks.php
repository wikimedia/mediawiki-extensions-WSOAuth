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

use Exception;
use Hooks;
use MediaWiki\Extension\PluggableAuth\Hook\PluggableAuthPopulateGroups;
use MediaWiki\Extension\PluggableAuth\PluggableAuthFactory;
use MediaWiki\Preferences\Hook\GetPreferencesHook;
use MediaWiki\User\UserGroupManager;
use MediaWiki\User\UserIdentity;
use MWException;
use OOUI\ButtonWidget;
use RequestContext;
use SpecialPage;
use User;

class WSOAuthHooks implements PluggableAuthPopulateGroups, GetPreferencesHook {
	/**
	 * @var PluggableAuthFactory
	 */
	private $pluggableAuthFactory;
	/**
	 * @var UserGroupManager
	 */
	private $userGroupManager;

	/**
	 * @param PluggableAuthFactory $pluggableAuthFactory
	 * @param UserGroupManager $userGroupManager
	 */
	public function __construct(
		PluggableAuthFactory $pluggableAuthFactory,
		UserGroupManager $userGroupManager
	) {
		$this->pluggableAuthFactory = $pluggableAuthFactory;
		$this->userGroupManager = $userGroupManager;
	}

	/**
	 * Adds the user to the groups defined via $wgOAuthAutoPopulateGroups after authentication.
	 *
	 * @param User $user
	 *
	 * @throws Exception
	 * @internal
	 */
	public function onPluggableAuthPopulateGroups( UserIdentity $user ): void {
		$currentPlugin = $this->pluggableAuthFactory->getInstance();
		if ( !( $currentPlugin instanceof WSOAuth ) ) {
			// We can only sync groups in the context of a WSOAuth authentication flow,
			// not for arbitrary other plugins
			return;
		}

		$result = Hooks::run( 'WSOAuthBeforeAutoPopulateGroups', [ &$user ] );

		if ( $result === false ) {
			return;
		}

		if ( !isset( $GLOBALS['wgOAuthAutoPopulateGroups'] ) ) {
			return;
		}

		$populateGroups = array_diff(
			(array)$GLOBALS['wgOAuthAutoPopulateGroups'],
			$this->userGroupManager->getUserEffectiveGroups( $user )
		);

		foreach ( $populateGroups as $group ) {
			$this->userGroupManager->addUserToGroup( $user, $group );
		}
	}

	/**
	 * Modify user preferences.
	 *
	 * @param User $user
	 * @param array &$preferences
	 *
	 * @throws MWException
	 */
	public function onGetPreferences( $user, &$preferences ) {
		RequestContext::getMain()->getOutput()->enableOOUI();
		$preferences_default = new ButtonWidget( [
			'href' => SpecialPage::getTitleFor( 'WSOAuthConnectRemote' )->getLinkURL(),
			'label' => wfMessage( 'wsoauth-manage-remotes' )->plain()
		] );

		$preferences += [ 'wsoauth-prefs-manage-remote' =>
			[
				'section' => 'personal/info',
				'label-message' => 'wsoauth-prefs-manage-remote',
				'type' => 'info',
				'raw' => true,
				'default' => (string)$preferences_default
			],
		];
	}
}
