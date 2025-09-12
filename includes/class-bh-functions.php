<?php
/*
 * BlackHaven Messenger Functions Class
 * Utility functions for the BlackHaven Messenger plugin.
 */

if (!defined('ABSPATH')) {
    exit;
}

class BH_Functions {

    public function __construct() {
        // Initialization code if needed
    }

    public function example_function() {
        // Example utility function
        return "This is an example function.";
    }

    /**
     * Generate a random access token.
     *
     * @param int $length Length of the token to generate.
     * @return string Generated token.
     */
    public static function generate_access_token($length = 32) {
        return bin2hex(random_bytes($length / 2));
    }

    /**
     * Validate an access token.
     *
     * @param string $token The token to validate.
     * @return bool True if valid, false otherwise.
     */
    public static function validate_access_token($token) {
        return preg_match('/^[a-f0-9]{64}$/', $token) === 1;
    }

    /**
     * Restrict direct access to plugin files by updating .htaccess.
     *
     * Presents a 404 for all files in the plugin directory.
     *
     * @return bool True on success, false on failure.
     */
    public static function restrict_plugin_access_htaccess() {
        $plugin_dir = dirname(__DIR__, 1); // Path to plugin directory
        $htaccess_file = $plugin_dir . '/.htaccess';

        $rules = <<<HTACCESS
    <IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} -f
    RewriteCond %{REQUEST_FILENAME} !index\.php$
    RewriteRule ^.*$ - [R=404,L]
    </IfModule>
    HTACCESS;

        // Write rules to .htaccess
        if (file_put_contents($htaccess_file, $rules) !== false) {
            return true;
        }
        return false;
    }
}
