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

/**
 * Class AuthProviderSessionFramework
 * @stable for subclassing
 */
abstract class AuthProviderFramework extends PluggableAuth {

	/** @var Session */
	private $session;

	/**
	 * AuthProviderSessionFramework constructor.
	 * @internal
	 */
	public function __construct() {
		$session_manager = \MediaWiki\Session\SessionManager::singleton();
		$this->session = $session_manager->getGlobalSession();
	}

	/**
	 * Exposes the set() method from MediaWiki\Session\Session.
	 *
	 * @param string $key
	 * @param string $value
	 */
	protected function setSessionVariable( $key, $value ) {
		$this->session->set( $key, $value );
	}

	/**
	 * Exposes the remove() method from MediaWiki\Session\Session.
	 *
	 * @param string $key
	 */
	protected function removeSessionVariable( $key ) {
		$this->session->remove( $key );
	}

	/**
	 * Exposes the get() method from MediaWiki\Session\Session.
	 *
	 * @param string $key
	 * @return null|string
	 */
	protected function getSessionVariable( $key ) {
		return $this->session->get( $key );
	}

	/**
	 * Exposes the exists() method from MediaWiki\Session\Session.
	 *
	 * @param string $key
	 * @return bool
	 */
	protected function doesSessionVariableExist( $key ) {
		return $this->session->exists( $key );
	}

	/**
	 * Exposes the save() method from MediaWiki\Session\Session.
	 */
	protected function saveSession() {
		$this->session->save();
	}
}
