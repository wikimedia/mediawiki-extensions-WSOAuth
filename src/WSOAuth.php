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

/**
 * Class WSOAuth
 */
class WSOAuth extends AuthProviderFramework
{
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
    public function __construct()
    {
        parent::__construct();

        if ($GLOBALS['wgOAuthUri'] !== false && $GLOBALS['wgOAuthClientId'] !== false && $GLOBALS['wgOAuthClientSecret'] !== false) {
            $this->auth_provider = WSOAuth::getAuthProvider();
        }
    }

    /**
     * @param $id
     * @param $username
     * @param $realname
     * @param $email
     * @param $errorMessage
     * @return bool
     * @throws FatalError
     * @throws MWException
     * @internal
     */
    public function authenticate(&$id, &$username, &$realname, &$email, &$errorMessage)
    {
        if (!isset($this->auth_provider)) {
            $errorMessage = wfMessage("wsoauth-not-configured-message")->parse();
            return false;
        }

        if ($this->doesSessionVariableExist("request_key") && $this->doesSessionVariableExist("request_secret")) {
            $key = $this->getSessionVariable("request_key");
            $secret = $this->getSessionVariable("request_secret");

            $this->removeSessionVariable("request_key");
            $this->removeSessionVariable("request_secret");

            $user_info = $this->auth_provider->getUser($key, $secret, $errorMessage);
            $hook = Hooks::run('WSOAuthAfterGetUser', [&$user_info, &$errorMessage]);

            // Request failed or user is not authorised.
            if ($user_info === false || $hook === false) {
                $errorMessage = !empty($errorMessage) ? $errorMessage : wfMessage('wsoauth-authentication-failure')->plain();
                return false;
            }

            $user_info['name'] = ucfirst($user_info['name']);

            if (!isset($user_info['name'])) {
                $errorMessage = wfMessage('wsoauth-invalid-username')->plain();
                return false;
            }

            $services = MediaWikiServices::getInstance();
            if(method_exists($services, 'getUserNameUtils')) {
                // MW 1.35 +
                $isValidUsername = $services->getUserNameUtils()->isValid($user_info['name']);
            } else {
                $isValidUsername = User::isValidUserName($user_info['name']);
            }
            if (!$isValidUsername) {
                $errorMessage = wfMessage('wsoauth-invalid-username')->plain();
                return false;
            }

            $username = $user_info['name']; // Required.
            $realname = isset($user_info['realname']) ? $user_info['realname'] : '';
            $email = isset($user_info['email']) ? $user_info['email'] : '';

            $user = User::newFromName($username);
            $user_id = $user->idForName();

            $id = $user_id === 0 ? null : $user_id;

            if (!is_null($user_id) && $user_id > 0 && !$this->userLoggedInThroughOAuth($user_id)) {
                // The user exists and has not logged in through OAuth
                if ($GLOBALS['wgOAuthMigrateUsersByUsername'] === false) {
                    $errorMessage = wfMessage('wsoauth-user-already-exists-message', $username)->plain();
                    return false;
                }

                // Usurp the account
                $this->saveExtraAttributes($user_id);
            }

            return true;
        }

        $result = $this->auth_provider->login($key, $secret, $auth_url);

        if ($result === false || empty($auth_url)) {
            $errorMessage = wfMessage('wsoauth-initiate-login-failure')->plain();
            return false;
        }

        $this->setSessionVariable('request_key', $key);
        $this->setSessionVariable('request_secret', $secret);
        $this->saveSession();

        header("Location: $auth_url");

        exit;
    }

    /**
     * @param User $user
     * @return void
     * @throws FatalError
     * @throws MWException
     * @internal
     */
    public function deauthenticate(User &$user)
    {
        Hooks::run('WSOAuthBeforeLogout', [&$user]);

        $this->auth_provider->logout($user);
    }

    /**
     * @param $id
     * @return void
     * @throws DBError
     * @internal
     */
    public function saveExtraAttributes($id)
    {
        $dbr = wfGetDB(DB_MASTER);
        $dbr->insert('wsoauth_users', ['wsoauth_user' => $id]);

        $this->auth_provider->saveExtraAttributes($id);
    }

    /**
     * Returns true if and only if the given ID exists in the table `wsoauth_users`.
     *
     * @param int $id
     * @return bool Whether or not this user was registered by WSOAuth.
     * @throws MWException
     */
    private function userLoggedInThroughOAuth($id)
    {
        if (!is_int($id)) throw new MWException("Given user ID is not an integer.");

        $dbr = wfGetDB(DB_REPLICA);
        return $dbr->numRows($dbr->select(
            'wsoauth_users',
            ['wsoauth_user'],
            'wsoauth_user = ' . $id
        )) === 1;
    }

    /**
     * Returns an instance of the configured auth provider.
     *
     * @return AuthProvider
     * @throws FatalError
     * @throws MWException
     * @throws InvalidAuthProviderClassException
     * @throws UnknownAuthProviderException
     * @internal
     */
    public static function getAuthProvider()
    {
        $auth_providers = array_merge(self::getAuthProviders(), (array)$GLOBALS['wgOAuthCustomAuthProviders']);
        $auth_provider = $GLOBALS['wgOAuthAuthProvider'];

        if (!isset($auth_providers[$auth_provider])) {
            throw new Exception\UnknownAuthProviderException(wfMessage('wsoauth-unknown-auth-provider-exception-message')->params($auth_provider)->plain());
        }

        if (!class_exists($auth_providers[$auth_provider])) {
            throw new Exception\InvalidAuthProviderClassException(wfMessage('wsoauth-unknown-auth-provider-class-exception-message')->plain());
        }

        if (!class_implements($auth_providers[$auth_provider])) {
            throw new Exception\InvalidAuthProviderClassException(wfMessage('wsoauth-invalid-auth-provider-class-exception-message')->plain());
        }

        return new $auth_providers[$auth_provider]();
    }

    /**
     * Returns the list of available auth providers.
     *
     * @return array
     * @throws FatalError
     * @throws MWException
     */
    public static function getAuthProviders()
    {
        $auth_providers = self::DEFAULT_AUTH_PROVIDERS;
        Hooks::run("WSOAuthGetAuthProviders", [&$auth_providers]);

        return $auth_providers;
    }

    /**
     * Adds the user to the groups defined via $wgOAuthAutoPopulateGroups after authentication.
     *
     * @param User $user
     * @return bool
     * @throws FatalError
     * @throws MWException
     * @internal
     */
    public static function onPluggableAuthPopulateGroups(User $user)
    {
        $result = Hooks::run('WSOAuthBeforeAutoPopulateGroups', [&$user]);

        if ($result === false) {
            return false;
        }

        if (!isset($GLOBALS['wgOAuthAutoPopulateGroups'])) {
            return false;
        }

        // Subtract the groups the user already has from the list of groups to populate.
        $populate_groups = array_diff((array)$GLOBALS['wgOAuthAutoPopulateGroups'], $user->getEffectiveGroups());

        foreach ($populate_groups as $populate_group) {
            $user->addGroup($populate_group);
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
    public static function onLoadExtensionSchemaUpdates(DatabaseUpdater $updater)
    {
        $directory = $GLOBALS['wgExtensionDirectory'] . '/WSOAuth/sql';
        $type = $updater->getDB()->getType();
        $sql_file = sprintf("%s/%s/table_wsoauth_users.sql", $directory, $type);

        if (!file_exists($sql_file)) {
            throw new MWException("WSOAuth does not support database type `$type`.");
        }

        $updater->addExtensionTable('wsoauth_users', $sql_file);
    }
}
