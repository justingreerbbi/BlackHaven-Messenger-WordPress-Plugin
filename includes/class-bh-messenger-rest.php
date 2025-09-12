<?php
if (! defined('ABSPATH')) {
    exit;
}

class BH_Messenger_REST {
    public function __construct() {
        add_action('rest_api_init', [$this, 'register_routes']);
    }

    public function register_routes() {
        register_rest_route('blackhaven-messenger/v1', '/authorize', [
            'methods'  => 'POST',
            'callback' => [$this, 'authorize'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route('blackhaven-messenger/v1', '/protected', [
            'methods'  => 'GET',
            'callback' => [$this, 'protected_endpoint'],
            'permission_callback' => [$this, 'check_access_token'],
        ]);

        register_rest_route('blackhaven-messenger/v1', '/users', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_users'],
            'permission_callback' => [$this, 'check_access_token'],
        ]);
    }

    /**
     * Check the request for a valid access token.
     * The token can be in the Authorization header as a Bearer token or as a query parameter.
     */
    public function check_access_token($request) {
        // Check for token in Authorization header or query parameter
        $auth_header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        $token = null;
        $user_id = null;

        if (preg_match('/Bearer\s(\S+)/', $auth_header, $matches)) {
            $token = $matches[1];
        }

        if (empty($token)) {
            return new WP_Error('no_token', 'Access token not provided', ['status' => 401]);
        }

        // Be very strict about not allowing tokens in query parameters. 
        // Tokens can be leaked in the logs.
        if (!empty($request->get_param('access_token'))) {
            return new WP_Error('invalid_request', 'Access token must be provided in the Authorization header', ['status' => 401]);
        }

        // Since the password is hashed, we need to lookup by the user_id and compare the hashed token
        $user_id = sanitize_text_field($request->get_param('user_id'));

        // No user ID provided.
        if (empty($user_id)) {
            return new WP_Error('no_user', 'User ID not provided', ['status' => 401]);
        }

        global $wpdb;
        $table = $wpdb->prefix . 'access_tokens';
        $current_time = date('Y-m-d H:i:s', current_time('timestamp'));

        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table WHERE user_id = %d AND expires_at > %s",
            $user_id,
            $current_time
        ));

        // Check the results and verify the token all in one step.
        if (! $row || ! wp_check_password($token, $row->token)) {
            return new WP_Error('invalid_request', 'Invalid request or expired token', ['status' => 401]);
        }

        // Attach user ID to request
        $request->set_param('user_id', $row->user_id);

        return true;
    }

    /**
     * Authorize Endpoint Method
     * 
     * @todo: Implement rate limiting and logging for security purposes.
     * @todo: Add option for number of allow access tokens per user and expiration time via settings.
     * @todo: Decide how we handle multiple tokens per user (e.g., invalidate old tokens, allow multiple, etc.).
     */
    public function authorize($request) {
        $params = $request->get_body_params();
        $username = sanitize_user($params['username'] ?? '');
        $password = $params['password'] ?? '';

        // Validate the user credentials.
        $user = wp_authenticate($username, $password);
        if (is_wp_error($user)) {
            return new WP_Error('invalid_login', 'Invalid username or password', ['status' => 401]);
        }

        global $wpdb;
        $table = $wpdb->prefix . 'access_tokens';

        // Only allow one token per user.
        $wpdb->delete($table, ['user_id' => $user->ID]);

        // Generate secure token.
        $token = bin2hex(random_bytes(32));
        $refresh_token = bin2hex(random_bytes(32));

        // Hash the token for storage.
        $hashed_token = wp_hash_password($token);
        $hashed_refresh_token = wp_hash_password($refresh_token);

        // Get the options for token expiry.
        $options = get_option('bh_messenger_advanced_options', []);
        $token_expiry = isset($options['access_token_lifetime']) ? intval($options['access_token_lifetime']) : 3600;

        // Set expiration time using WordPress timezone.
        $current_time = current_time('timestamp'); // Local timestamp
        $created = date('Y-m-d H:i:s', $current_time);

        // If the access token lifetime is set to 0 or less, make the token never expire (somewhat).
        // If the setting is 0 for never expire, we set it to 10 years from now. 10 Years is enough.
        // If you are reading this, never expiring is a HUGE no no for security reasons but I will cave for this.
        if ($token_expiry <= 0) {
            $expires = date('Y-m-d H:i:s', strtotime('+10 years', $current_time));
        } else {
            $expires = date('Y-m-d H:i:s', $current_time + $token_expiry);
        }

        // Filter Expiration Time.
        $expires = apply_filters('blackhaven_messenger_authorize_access_token_expires', $expires);

        // By default, we will only return the user ID.
        $user_info = array(
            'ID' => (int) $user->ID,
        );

        // Allow for filtering the user information.
        $user_info = apply_filters('blackhaven_messenger_authorize_user_info_data', $user_info, $user);

        // Insert the token into the database.
        $insert = $wpdb->insert($table, [
            'user_id'    => $user->ID,
            'token'      => $hashed_token,
            'refresh_token' => $hashed_refresh_token,
            'expires_at' => $expires,
            'created_at' => $created
        ]);

        if ($insert === false) {
            return new WP_Error('db_error', 'Database error. Please contact your system administrator.', ['status' => 500]);
        }

        return [
            'success' => true,
            'token'   => $token,
            'refresh_token' => $refresh_token,
            'expires' => $expires,
            'created' => $created,
            'user_data' => $user_info,
        ];
    }

    /**
     * Example Protected Endpoint
     */
    public function protected_endpoint($request) {
        $user_id = $request->get_param('user_id');
        return [
            'success' => true,
            'message' => 'You have access!',
            'user_id' => (int) $user_id,
        ];
    }

    /**
     * Return a list of the users.
     *
     * @todo: We need to add a way where the admin can allow which users are chat users.
     */
    public function get_users() {
        $users = get_users();
        $user_list = [];
        foreach ($users as $user) {
            $user_list[] = [
                'ID'       => (int) $user->ID,
                'display_name' => $user->display_name,
            ];
        }
        return $user_list;
    }

    public functio
}
