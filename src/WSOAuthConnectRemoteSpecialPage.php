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

use MediaWiki\Session\SessionManager;

/**
 * Class WSOAuthConnectRemoteSpecialPage
 *
 * This class implements the special page Special:WSOAuthConnectRemote.
 */
class WSOAuthConnectRemoteSpecialPage extends SpecialPage {
	/**
	 * @inheritDoc
	 */
	public function __construct() {
		parent::__construct( "WSOAuthConnectRemote", "", false );
	}

	/**
	 * @inheritDoc
	 */
	public function getDescription() {
		return $this->msg( 'wsoauth-connect-remote-special-page-header' )->parse();
	}

	/**
	 * @inheritDoc
	 * @throws MWException
	 */
	public function execute( $parameter ) {
		$this->requireLogin();
		$this->setHeaders();

		$user_id = $this->getUser()->getId();

		if ( WSOAuth::userLoggedInThroughOAuth( $user_id ) ) {
			$this->getOutput()->addHTML( $this->msg( "wsoauth-account-already-coupled" )->parse() );
			return;
		}

		$global_session = SessionManager::getGlobalSession();
		$global_session->persist();

		$login_token = $global_session->getToken( '', 'login' );

		$form = new OOUIHTMLForm( [
			"wpName" => [
				"type" => "hidden",
				"name" => "wpName",
				"default" => ""
			],
			"wpPassword" => [
				"type" => "hidden",
				"name" => "wpPassword",
				"default" => ""
			],
			"pluggableauthlogin" => [
				"type" => "hidden",
				"name" => "pluggableauthlogin",
				"default" => "Log in with OAuth"
			],
			"wpEditToken" => [
				"type" => "hidden",
				"name" => "wpEditToken",
				"default" => "+\\"
			],
			"title" => [
				"type" => "hidden",
				"name" => "title",
				"default" => "Special:UserLogin"
			],
			"authAction" => [
				"type" => "hidden",
				"name" => "authAction",
				"default" => "login"
			],
			"force" => [
				"type" => "hidden",
				"name" => "force",
				"default" => ""
			],
			"wpLoginToken" => [
				"type" => "hidden",
				"name" => "wpLoginToken",
				"default" => $login_token
			]
		] );

		$form->setWrapperLegendMsg( "wsoauth-connect-remote-special-page-wrapper-legend" );
		$form->setTitle( $this->getFullTitle() );
		$form->setAction( SpecialPage::getTitleFor( 'Userlogin' )->getLinkURL() );
		$form->setHeaderText( $this->msg( "wsoauth-connect-remote-special-page-description" )->parse() );
		$form->setSubmitText( $this->msg( "wsoauth-pluggable-auth-button-label-message" )->parse() );

		$form->show();
	}
}
