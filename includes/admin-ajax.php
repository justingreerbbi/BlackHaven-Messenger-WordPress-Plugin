<?php
// Exit if accessed directly
if (! defined('ABSPATH')) {
    exit;
}

// Check for AJAX request
if (! defined('DOING_AJAX') || ! DOING_AJAX) {
    wp_die('No direct access allowed.');
}

// Example: Handle a custom AJAX action
add_action('wp_ajax_blackhaven_messenger_action', 'blackhaven_messenger_ajax_handler');
function blackhaven_messenger_ajax_handler() {
    // Your AJAX logic here

    // Example response
    wp_send_json_success(array(
        'message' => 'AJAX request received.',
    ));
}
