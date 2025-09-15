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

// Define Database Tables Constants
define('BH_TABLE_ACCESS_TOKENS', 'bh_access_tokens');
define('BH_TABLE_CONVERSATIONS', 'bh_conversations');
define('BH_TABLE_CONVERSATION_MEMBERS', 'bh_conversation_members');
define('BH_TABLE_MESSAGES', 'bh_messages');
define('BH_TABLE_USER_KEYS', 'bh_user_keys');
define('BH_TABLE_CONVERSATION_KEYS', 'bh_conversation_keys');

// Redirect the user the the connection information screen on plugin activation.
// Not sure if this is the best way to do this, but it seems to work. This is important for UX.
add_action('activated_plugin', function ($plugin) {
    if ($plugin === plugin_basename(__FILE__)) {
        wp_safe_redirect(admin_url('admin.php?page=blackhaven-messenger-connection&status=welcome'));
        exit;
    }
});

/**
 * Plugin Activation Hook.
 */
function bh_messenger_activate() {

    // Add the default options for the plugin if they do not exist.
    if (get_option('bh_messenger_options') === false) {
        $default_options = array(
            'enable_api' => 1,
        );
        add_option('bh_messenger_options', $default_options);
    }

    // Do the same for bh_messenger_advanced_options
    if (get_option('bh_messenger_advanced_options') === false) {
        $default_advanced_options = array(
            'access_token_lifetime' => 3600, // 1 hour
            'remove_data_on_deactivation' => 0,
        );
        add_option('bh_messenger_advanced_options', $default_advanced_options);
    }

    global $wpdb;
    $charset_collate = $wpdb->get_charset_collate();
    $access_token_table = $wpdb->prefix . BH_TABLE_ACCESS_TOKENS; // @todo: Look at adding our own prefix to avoid conflicts.
    $conversations_table = $wpdb->prefix . BH_TABLE_CONVERSATIONS;
    $conversation_members_table = $wpdb->prefix . BH_TABLE_CONVERSATION_MEMBERS;
    $messages_table = $wpdb->prefix . BH_TABLE_MESSAGES;
    $user_keys_table = $wpdb->prefix . BH_TABLE_USER_KEYS;
    $conversation_keys_table = $wpdb->prefix . BH_TABLE_CONVERSATION_KEYS;

    $sql1 = "CREATE TABLE $access_token_table (
        ID BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT(20) UNSIGNED NOT NULL,
        token VARCHAR(64) NOT NULL,
        refresh_token VARCHAR(64) DEFAULT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        KEY user_id (user_id),
        KEY token (token)
    ) $charset_collate;";

    $sql2 = "CREATE TABLE $conversations_table (
        ID BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        type ENUM('private','group') NOT NULL,
        created_by BIGINT UNSIGNED NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES {$wpdb->prefix}users(ID)
    ) $charset_collate;";

    $sql3 = "CREATE TABLE $conversation_members_table (
        conversation_id BIGINT UNSIGNED NOT NULL,
        user_id BIGINT UNSIGNED NOT NULL,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (conversation_id, user_id),
        FOREIGN KEY (conversation_id) REFERENCES {$wpdb->prefix}conversations(ID),
        FOREIGN KEY (user_id) REFERENCES {$wpdb->prefix}users(ID)
    ) $charset_collate;";

    $sql4 = "CREATE TABLE $messages_table (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        conversation_id BIGINT UNSIGNED NOT NULL,
        sender_id BIGINT UNSIGNED NOT NULL,
        encrypted_text TEXT,
        file_path VARCHAR(255) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (conversation_id) REFERENCES {$wpdb->prefix}conversations(ID),
        FOREIGN KEY (sender_id) REFERENCES {$wpdb->prefix}users(ID),
        INDEX idx_conversation_time (conversation_id, created_at)
    ) $charset_collate;";

    $sql5 = "CREATE TABLE $user_keys_table (
        user_id BIGINT UNSIGNED NOT NULL,
        public_key VARBINARY(255) NOT NULL,
        key_type ENUM('identity', 'signed_prekey', 'one_time_prekey') DEFAULT 'identity',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NULL DEFAULT NULL,
        PRIMARY KEY (user_id, key_type),
        FOREIGN KEY (user_id) REFERENCES {$wpdb->prefix}users(ID) ON DELETE CASCADE
    ) $charset_collate;";

    $sql6 = "CREATE TABLE $conversation_keys_table (
        conversation_id BIGINT UNSIGNED NOT NULL,
        user_id BIGINT UNSIGNED NOT NULL,
        encrypted_key VARBINARY(512) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (conversation_id, user_id),
        FOREIGN KEY (conversation_id) REFERENCES {$wpdb->prefix}conversations(id),
        FOREIGN KEY (user_id) REFERENCES {$wpdb->prefix}users(ID)
    ) $charset_collate;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql1);
    dbDelta($sql2);
    dbDelta($sql3);
    dbDelta($sql4);
    dbDelta($sql5);
    dbDelta($sql6);
}
register_activation_hook(__FILE__, 'bh_messenger_activate');

/**
 * Plugin Deactivation Hook.
 */
function bh_messenger_deactivate() {

    // If the user has choosen to remove data on deactivation, do so.
    $options = get_option('bh_messenger_advanced_options', []);
    if (isset($options['remove_data_on_deactivation']) && $options['remove_data_on_deactivation']) {

        // Remove all plugin options.
        delete_option('bh_messenger_options');
        delete_option('bh_messenger_advanced_options');

        // Remove all plugin tables.
        global $wpdb;
        $access_token_table = $wpdb->prefix . BH_TABLE_ACCESS_TOKENS;
        $conversations_table = $wpdb->prefix . BH_TABLE_CONVERSATIONS;
        $conversation_members_table = $wpdb->prefix . BH_TABLE_CONVERSATION_MEMBERS;
        $messages_table = $wpdb->prefix . BH_TABLE_MESSAGES;
        $user_keys_table = $wpdb->prefix . BH_TABLE_USER_KEYS;
        $conversation_keys_table = $wpdb->prefix . BH_TABLE_CONVERSATION_KEYS;

        // Note: The order of removal is important due to foreign key constraints. Took me forever to figure that out.
        // Drop tables in order to avoid foreign key constraint errors.
        $wpdb->query("DROP TABLE IF EXISTS $conversation_keys_table");
        $wpdb->query("DROP TABLE IF EXISTS $user_keys_table");
        $wpdb->query("DROP TABLE IF EXISTS $conversation_members_table");
        $wpdb->query("DROP TABLE IF EXISTS $messages_table");
        $wpdb->query("DROP TABLE IF EXISTS $conversations_table");
        $wpdb->query("DROP TABLE IF EXISTS $access_token_table");
    }
}
register_deactivation_hook(__FILE__, 'bh_messenger_deactivate');

// Add a JS confirmation dialog on plugin deactivation if "remove_data_on_deactivation" is enabled.
// Just to be sure the user knows what they are doing to the fullest extent possible.
add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($actions) {
    $options = get_option('bh_messenger_advanced_options', []);
    if (!empty($options['remove_data_on_deactivation'])) {
        $deactivate_url = isset($actions['deactivate']) ? $actions['deactivate'] : '';
        if ($deactivate_url) {
            $confirm_message = esc_js(__('Warning: According to your settings, deactivating BlackHaven Messenger will remove all plugin data including messages, settings, access tokens, etc. There will be no trace of this plugin. Are you sure you want to continue?', 'blackhaven-messenger'));
            $actions['deactivate'] = str_replace(
                '<a ',
                '<a onclick="return confirm(\'' . $confirm_message . '\')" ',
                $deactivate_url
            );
        }
    }
    return $actions;
});

// -------- Includes --------
require_once BH_MESSENGER_DIR . 'includes/class-bh-functions.php';      // Plugin Functions Class
require_once BH_MESSENGER_DIR . 'includes/class-bh-options.php';        // Options Page Class
require_once BH_MESSENGER_DIR . 'includes/class-bh-messenger-rest.php'; // REST API Class
require_once BH_MESSENGER_DIR . 'includes/class-bh-security-audit.php'; // Security Audit Class
require_once BH_MESSENGER_DIR . 'includes/class-bh-cronjobs.php';

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
$options = get_option('bh_messenger_option', []);
if (!empty($options['enable_api'])) {
    new BH_Messenger_REST();
}
