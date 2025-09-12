<?php

/**
 * Plugin Name: BlackHaven Messenger
 * Description: BlackHaven Messenger is a real-time encrypted chat plugin for WordPress and the BlackHaven Messenger Mobile App.
 * Version: 1.0.0
 * Author: BlackHaven Dynamics
 * Author URI: https://blackhaven.io
 * Text Domain: blackhaven-messenger
 * Domain Path: /languages
 * License: GPL2
 */

if (! defined('ABSPATH')) {
    exit;
}

// Define constants
define('BH_MESSENGER_PLUGIN_VERSION', '1.0.0');
define('BH_MESSENGER_DIR', plugin_dir_path(__FILE__));
define('BH_DB_VERSION', '1.0');

// -------- Activation / Deactivation --------
function bh_messenger_activate() {
    add_option('bh_messenger_option', 'default_value');

    global $wpdb;
    $charset_collate = $wpdb->get_charset_collate();
    $table_name = $wpdb->prefix . 'access_tokens';

    $sql1 = "CREATE TABLE $table_name (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT(20) UNSIGNED NOT NULL,
        token VARCHAR(64) NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        KEY user_id (user_id),
        KEY token (token)
    ) $charset_collate;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql1);
}
register_activation_hook(__FILE__, 'bh_messenger_activate');

function bh_messenger_deactivate() {
    // cleanup if needed
}
register_deactivation_hook(__FILE__, 'bh_messenger_deactivate');

// -------- Includes --------
require_once BH_MESSENGER_DIR . 'includes/class-bh-functions.php';      // Plugin Functions Class
require_once BH_MESSENGER_DIR . 'includes/class-bh-options.php';        // Options Page Class
require_once BH_MESSENGER_DIR . 'includes/class-bh-messenger-rest.php'; // REST API Class
require_once BH_MESSENGER_DIR . 'includes/class-bh-security-audit.php'; // Security Audit Class

// -------- Bootstrap the functions singleton --------
add_action('plugins_loaded', 'bhm_bootstrap_functions_singleton', 5);
function bhm_bootstrap_functions_singleton() {
    if (! isset($GLOBALS['bh_functions']) || ! $GLOBALS['bh_functions'] instanceof BH_Functions) {
        $GLOBALS['bh_functions'] = new BH_Functions();
    }
}

/** Convenience accessor (so you can call bh_functions()->method()) */
function bh_functions() {
    if (! isset($GLOBALS['bh_functions']) || ! $GLOBALS['bh_functions'] instanceof BH_Functions) {
        $GLOBALS['bh_functions'] = new BH_Functions();
    }
    return $GLOBALS['bh_functions'];
}

// -------- Init the Options Page class (it hooks into admin_* itself) --------
add_action('plugins_loaded', function () {

    // Load menu and other features only for admins that have permission.
    if (is_admin() && current_user_can('manage_options')) {
        new BH_Messenger_Options();
        new BH_Security_Audit();
        require_once BH_MESSENGER_DIR . 'includes/admin-actions.php';
    }

    // Load admin AJAX and form handlers only in admin or AJAX context.
    if (is_admin() && defined('DOING_AJAX')) {
        require_once BH_MESSENGER_DIR . 'includes/admin-ajax.php';
    }
}, 10);


// -------- REST bootstrap --------
// @todo: Enable this behind an option to have the API active.
new BH_Messenger_REST();
