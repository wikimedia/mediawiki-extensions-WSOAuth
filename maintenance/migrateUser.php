<?php

use Exception\InvalidAuthProviderClassException;
use Exception\InvalidUsernameException;
use Exception\UnknownAuthProviderException;
use Wikimedia\Rdbms\IResultWrapper;

/*
 * Load the required class
 */
if (getenv( 'MW_INSTALL_PATH' ) !== false) {
    require_once getenv('MW_INSTALL_PATH') . '/maintenance/Maintenance.php';
} else {
    require_once __DIR__ . '/../../../maintenance/Maintenance.php';
}

/**
 * Class MigrateUser
 */
class MigrateUser extends Maintenance
{
    /**
     * MigrateUser constructor.
     *
     * @inheritDoc
     */
    public function __construct()
    {
        parent::__construct();

        $this->addOption( 'quick', 'Skip the 5 second countdown before migrating a user' );
        $this->addOption('user', 'Username of the account to migrate to WSOAuth (usurp), or `*` to migrate all existing accounts.', true, true);
        $this->addOption('migrate-all', 'If and only if this option is provided will a wildcard (`*`) be accepted as the user.');

        $this->requireExtension('WSOAuth');
    }

    /**
     * @inheritDoc
     */
    public function execute()
    {
        $user = $this->getOption( 'user' );

        if ($user === "*") {
            $is_allowed = $this->getOption('migrate-all');

            if (!$is_allowed) {
                $this->fatalError("Please provide the option `--migrate-all` to enable wildcards.");
            }

            $confirmation = $this->confirm();

            if ( $confirmation !== "yes") {
                $this->fatalError("Migration aborted.");
            }

            try {
                $this->migrateAllUsers([$this, 'updateStatus']);
            } catch(Exception $e) {
                $this->fatalError("Something went wrong while importing a user: " . $e->getMessage());
            }

            $this->output("\n");
            $this->output("\t... done ... \n");
        } else {
            if (!$this->getOption('quick', false)) {
                $this->output("Abort the migration of user `$user` with control-c in the next five seconds... ");
                $this->countDown(5);
            }

            $this->output("\n");
            $this->output("Migrating user ...\n");

            try {
                if ($this->migrateByUsername($user)) {
                    $this->output("\t... done ...\n");
                } else {
                    $this->output("\t... done, user already migrated ...\n");
                };
            } catch(InvalidUsernameException $e) {
                $this->fatalError("Please provide the username of an existing user.");
            } catch(Exception $e) {
                $this->fatalError("Something went wrong while importing the given user: " . $e->getMessage());
            }
        }
    }

    /**
     * @param bool $callback
     * @throws InvalidAuthProviderClassException
     * @throws UnknownAuthProviderException
     */
    private function migrateAllUsers($callback = false)
    {
        if ($callback && !is_callable($callback)) {
            $this->fatalError("Invalid callback.");
        }

        $instance = new WSOAuth();

        $dbr = wfGetDB(DB_MASTER);
        $users = $dbr->select('user', 'user_id');
        $migrated_users = $dbr->select('wsoauth_users', 'wsoauth_user');

        $users = $this->resultToArray($users, 'user_id');
        $migrated_users = $this->resultToArray($migrated_users, 'wsoauth_user');

        $migration_users = array_diff($users, $migrated_users);

        $total = count($migration_users);
        $current = 0;

        if ($callback) {
            $callback($current, $total);
        }

        foreach ($migration_users as $user) {
            $current++;

            $this->migrateUser($instance, $user);

            if ($callback) {
                $callback($current, $total);
            }
        }
    }

    /**
     * @param $username
     * @return bool True if the user got migrated, false if the user was already migrated
     * @throws InvalidUsernameException
     * @throws Exception
     */
    private function migrateByUsername($username)
    {
        if (!is_string($username)) {
            throw new Exception("`username` must be of type `string`, `" . gettype($username) . "` given");
        }

        if (empty($username)) {
            throw new InvalidUsernameException();
        }

        $id = User::idFromName($username);

        if ($id === null) {
            throw new InvalidArgumentException();
        }

        $instance = new WSOAuth();
        return $this->migrateUser($instance, $id);
    }

    /**
     * @param WSOAuth $instance
     * @param $id
     * @return bool
     */
    private function migrateUser(WSOAuth $instance, $id)
    {
        if (!is_int($id) && (!is_string($id) || !ctype_digit($id))) {
            throw new InvalidArgumentException(
                '`id` must be an integer or a numeric string'
            );
        }

        if ($this->isUserMigrated($id)) {
            return false;
        }

        $instance->saveExtraAttributes($id);

        return true;
    }

    /**
     * @param int $current The number of users migrated
     * @param int $total The total number of users to migrate
     */
    private function updateStatus($current, $total)
    {
        $this->output(
            "\rMigrating users ... \t {$this->getProgress($current, $total)}% ({$current}/{$total})"
        );
    }

    /**
     * @param $current
     * @param $total
     * @return string
     */
    private function getProgress($current, $total)
    {
        return (string)($current === 0 ? 100 : floor(($current / $total) * 100));
    }

    /**
     * @param $id
     * @return bool
     */
    private function isUserMigrated($id)
    {
        $dbr = wfGetDB(DB_MASTER);
        return $dbr->select('wsoauth_users', 'wsoauth_user', ['wsoauth_user' => $id])->numRows() > 0;
    }

    /**
     * @param IResultWrapper $wrapper
     * @param $key
     * @return array
     */
    private function resultToArray(IResultWrapper $wrapper, $key)
    {
        $result = [];
        foreach($wrapper as $value) {
            $result[] = $value->$key;
        }

        return $result;
    }

    /**
     * Prompts the user for confirmation and returns the user's response (or initializes a countdown and
     * returns "yes" if no response could be retrieved).
     *
     * @return string
     */
    private function confirm()
    {
        if (PHP_OS == "WINNT") {
            $this->output("Please confirm the migration of ALL users on this wiki by typing `yes` in the console and pressing enter: ");
            $confirmation = stream_get_line(STDIN, 1024, PHP_EOL);
        } elseif (function_exists('readline')) {
            $this->output("Please confirm the migration of ALL users on this wiki by typing `yes` in the console and pressing enter: ");
            $confirmation = readline();
        } else {
            $this->output("Abort the migration of ALL users with control-c in the next nine seconds... ");
            $this->countDown(9);
            $confirmation = "yes";
        }

        $this->output("\n");

        return $confirmation;
    }
}

$maintClass = MigrateUser::class;
require_once RUN_MAINTENANCE_IF_MAIN;