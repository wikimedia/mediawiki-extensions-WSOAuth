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
 * Interface AuthProvider
 * @stable for implementation
 */
interface AuthProvider {
	/**
	 * Log in the user through the external OAuth provider.
	 *
	 * @param &$key string The consumer key returned by the OAuth provider. May be left empty.
	 * @param &$secret string The consumer secret returned by the OAuth provider. May be left empty.
	 * @param &$auth_url string The URL the user must be redirected to. Must not be left empty.
	 * @return boolean Returns true on successful login, false otherwise.
	 * @internal
	 */
	public function login( &$key, &$secret, &$auth_url );

	/**
	 * Log out the user and destroy the session.
	 *
	 * @param \User &$user
	 * @return void
	 * @internal
	 */
	public function logout( \User &$user );

	/**
	 * Get user info from session. Returns false when the request failed or the user is not authorised.
	 *
	 * @param $key string The consumer key set during login().
	 * @param $secret string The consumer secret set during login().
	 * @param string &$errorMessage Message shown to the user when there is an error.
	 * @return boolean|array Returns an array with at least a 'name' when the user is authenticated, returns false when the user is not authorised or the authentication failed.
	 * @internal
	 */
	public function getUser( $key, $secret, &$errorMessage );

	/**
	 * Gets called whenever a user is successfully authenticated, so extra attributes about the user can be saved.
	 *
	 * @param int $id The ID of the User
	 * @return void
	 * @internal
	 */
	public function saveExtraAttributes( $id );
}
