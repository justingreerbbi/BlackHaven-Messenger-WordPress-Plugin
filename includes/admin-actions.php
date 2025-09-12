<?php
// Exit if accessed directly.
if (! defined('ABSPATH')) {
    exit;
}

/**
 * Handle admin form submissions.
 */
function blackhaven_messenger_handle_admin_form() {
    // Check nonce for security.
    if (
        ! isset($_POST['blackhaven_messenger_nonce']) ||
        ! wp_verify_nonce($_POST['blackhaven_messenger_nonce'], 'blackhaven_messenger_action')
    ) {
        wp_die(__('Security check failed', 'blackhaven-messenger'));
    }

    // Check user capabilities.
    if (! current_user_can('manage_options')) {
        wp_die(__('Insufficient permissions', 'blackhaven-messenger'));
    }

    // Sanitize and process form data.
    $data = isset($_POST['blackhaven_messenger_data']) ? sanitize_text_field($_POST['blackhaven_messenger_data']) : '';

    // Example: Save option.
    update_option('blackhaven_messenger_data', $data);

    // Redirect back with success message.
    wp_redirect(add_query_arg('message', 'success', wp_get_referer()));
    exit;
}
add_action('admin_post_blackhaven_messenger_form', 'blackhaven_messenger_handle_admin_form');
