<?php
if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Delete plugin options
delete_option('blackhaven_messenger_option');

// If multisite, cleanup for all sites
if (is_multisite()) {
    global $wpdb;
    $blog_ids = $wpdb->get_col("SELECT blog_id FROM {$wpdb->blogs}");
    foreach ($blog_ids as $blog_id) {
        switch_to_blog($blog_id);
        delete_option('my_plugin_option');
        restore_current_blog();
    }
}
