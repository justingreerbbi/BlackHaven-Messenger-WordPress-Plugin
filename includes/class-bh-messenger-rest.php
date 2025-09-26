<?php

/**
 * BlackHaven Messenger REST API Class
 * Handles all REST API endpoints for the BlackHaven Messenger plugin.
 * 
 * @package BlackHavenMessenger
 * @todo: Instead of allowing user_id in the request, we should restructure the API to get the user ID from the URL. We still need to look into masking the ID of the user though as well.
 */
if (! defined('ABSPATH')) {
    exit;
}

class BH_Messenger_REST {
    public function __construct() {
        add_action('rest_api_init', [$this, 'register_routes']);
    }

    /**
     * Register REST API routes.
     */
    public function register_routes() {
        // Authorization Route.
        register_rest_route('blackhaven-messenger/v1', '/authorize', [
            'methods'  => 'POST',
            'callback' => [$this, 'authorize'],
            'permission_callback' => '__return_true',
        ]);

        // Initial Payload Route.
        register_rest_route('blackhaven-messenger/v1', '/payload', [
            'methods'  => 'POST',
            'callback' => [$this, 'initial_payload'],
            'permission_callback' => [$this, 'check_access_token'],
        ]);

        // Add User Public Key Route.
        register_rest_route('blackhaven-messenger/v1/identity', '/sync', [
            'methods'  => 'POST',
            'callback' => [$this, 'add_user_keys'],
            'permission_callback' => [$this, 'check_access_token'],
        ]);

        // Get Users Route.
        register_rest_route('blackhaven-messenger/v1', '/users', [
            'methods'  => 'POST',
            'callback' => [$this, 'get_users'],
            'permission_callback' => [$this, 'check_access_token'],
        ]);

        // Get Conversations Route
        register_rest_route('blackhaven-messenger/v1', '/conversations', [
            'methods'  => 'POST',
            'callback' => [$this, 'get_conversations'],
            'permission_callback' => [$this, 'check_access_token'],
        ]);

        // Start Private Conversation Route
        register_rest_route('blackhaven-messenger/v1/conversations/', '/start-private', [
            'methods'  => 'POST',
            'callback' => [$this, 'start_private_conversation'],
            'permission_callback' => [$this, 'check_access_token'],
        ]);

        // Start Group Conversation Route
        register_rest_route('blackhaven-messenger/v1/conversations/', '/start-group', [
            'methods'  => 'POST',
            'callback' => [$this, 'start_group_conversation'],
            'permission_callback' => [$this, 'check_access_token'],
        ]);

        // Get Conversation Messages Route
        register_rest_route('blackhaven-messenger/v1/conversations/', '/get-messages', [
            'methods'  => 'POST',
            'callback' => [$this, 'get_conversation_messages'],
            'permission_callback' => [$this, 'check_access_token'],
            'args' => [
                'conversation_id' => [
                    'validate_callback' => function ($param, $request, $key) {
                        return is_numeric($param) && intval($param) > 0;
                    }
                ]
            ]
        ]);

        // Send Message Route
        register_rest_route('blackhaven-messenger/v1/conversations/', '/send-message', [
            'methods'  => 'POST',
            'callback' => [$this, 'send_message'],
            'permission_callback' => [$this, 'check_access_token'],
            'args' => [
                'conversation_id' => [
                    'validate_callback' => function ($param, $request, $key) {
                        return is_numeric($param) && intval($param) > 0;
                    }
                ]
            ]
        ]);
    }

    /**
     * Check the request for a valid access token.
     * The token can be in the Authorization header as a Bearer token or as a query parameter.
     * 
     * @param WP_REST_Request $request
     * @return true|WP_Error
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
        $table = $wpdb->prefix . BH_TABLE_ACCESS_TOKENS;
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
     * 
     * @param WP_REST_Request $request
     * @return array|WP_Error
     */
    public function authorize($request) {
        $params = $request->get_body_params();
        if (empty($params)) {
            $params = json_decode($request->get_body(), true) ?? [];
        }
        $username = sanitize_user($params['username'] ?? '');
        $password = $params['password'] ?? '';

        // Validate the user credentials.
        $user = wp_authenticate($username, $password);
        if (is_wp_error($user)) {
            return new WP_Error('invalid_login', 'Invalid username or password', ['status' => 401]);
        }

        global $wpdb;
        $table = $wpdb->prefix . BH_TABLE_ACCESS_TOKENS;

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
     * Initial Payload Endpoint Method
     * Initial Payload Endpoint Method
     *
     * @todo: Add in hook for additonal data to be added to the payload.
     * @todo: Add in a hook for server version comparison to force updates and limit insecure server/client versions.
     */
    public function initial_payload($request) {
        $params = $request->get_body_params();
        if (empty($params)) {
            $params = json_decode($request->get_body(), true) ?? [];
        }
        $user_id = intval($request->get_param('user_id'));

        global $wpdb;

        // Get users with a user key set
        $user_keys_table = $wpdb->prefix . BH_TABLE_USER_KEYS;
        $users = $wpdb->get_results("
            SELECT u.ID, u.display_name, uk.ik_pub_b64, uk.sig_pub_b64, uk.spk_pub_b64, uk.spk_sig_b64
            FROM {$user_keys_table} uk
            INNER JOIN {$wpdb->users} u ON u.ID = uk.user_id
            GROUP BY u.ID
        ");

        // Remove current user from the users list
        // @todo: This does not seem to work as expected. Look into it.
        $users = array_filter($users, function ($user) use ($user_id) {
            return $user->ID !== $user_id;
        });

        // Get conversations for the authenticated user (do not expose user_id in response)
        $conversations_table = $wpdb->prefix . BH_TABLE_CONVERSATIONS;
        $conversation_members_table = $wpdb->prefix . BH_TABLE_CONVERSATION_MEMBERS;

        $conversations = $wpdb->get_results($wpdb->prepare(
            "SELECT c.* FROM {$conversations_table} c
             JOIN {$conversation_members_table} cm ON c.ID = cm.conversation_id
             WHERE cm.user_id = %d",
            $user_id
        ));

        // For each conversation, get members and their keys
        foreach ($conversations as &$conversation) {
            // Get members
            $members = $wpdb->get_results($wpdb->prepare(
                "SELECT u.ID, u.display_name, uk.public_key, uk.key_type, uk.expires_at
             FROM {$conversation_members_table} cm
             JOIN {$wpdb->users} u ON cm.user_id = u.ID
             LEFT JOIN {$user_keys_table} uk ON uk.user_id = u.ID
             WHERE cm.conversation_id = %d",
                $conversation->ID
            ));
            $conversation->members = $members;

            // Get latest message
            $latest_message = $wpdb->get_row($wpdb->prepare(
                "SELECT m.ID, m.sender_id, m.encrypted_text, m.created_at
             FROM {$wpdb->prefix}" . BH_TABLE_MESSAGES . " m
             WHERE m.conversation_id = %d
             ORDER BY m.created_at DESC, m.ID DESC
             LIMIT 1",
                $conversation->ID
            ));
            $conversation->latest_message = $latest_message;

            $conversation->chat_name = '';
            if ($conversation->type === 'private' && count($members) === 2) {

                // For private chats, set the chat name to the other user's display name
                foreach ($members as $member) {
                    if ((int)$member->ID !== (int)$user_id) {
                        $conversation->chat_name = $member->display_name;
                        break;
                    }
                }
            } elseif ($conversation->type === 'group') {

                // @todo: Give every member the ability to set a group chat name.
                // For group chats, we can set a default name or leave it blank for now
                $conversation->chat_name = 'Group Chat';
            }
        }

        return [
            'users' => $users,
            'conversations' => $conversations
        ];
    }

    /**
     * Set or update a user's public key.
     * This is used by the client to set their public key for end-to-end encryption.
     * 
     * @param WP_REST_Request $request
     * @return array|WP_Error
     */
    public function add_user_keys($request) {
        $params = $request->get_body_params();
        if (empty($params)) {
            $params = json_decode($request->get_body(), true) ?? [];
        }

        $user_id = intval($params['user_id'] ?? 0);
        $ik_pub  = sanitize_text_field($params['ik_pub_b64']);
        $sig_pub = sanitize_text_field($params['sig_pub_b64']);
        $spk_pub = sanitize_text_field($params['spk_pub_b64']);
        $spk_sig = sanitize_text_field($params['spk_sig_b64']);

        $key_type = $params['key_type'] ?? 'identity';
        $expires_at = isset($params['expires_at']) ? date('Y-m-d H:i:s', strtotime($params['expires_at'])) : null;

        if (!$user_id || empty($ik_pub) || empty($sig_pub) || empty($spk_pub) || empty($spk_sig)) {
            return new WP_Error('invalid_params', 'Missing required parameters.', ['status' => 400]);
        }

        global $wpdb;
        $table = $wpdb->prefix . BH_TABLE_USER_KEYS;

        // Insert or update the user key
        $insert = $wpdb->replace($table, [
            'user_id' => $user_id,
            'ik_pub_b64'   => $ik_pub,
            'sig_pub_b64'  => $sig_pub,
            'spk_pub_b64'  => $spk_pub,
            'spk_sig_b64'  => $spk_sig,
        ]);

        if ($insert === false) {
            return new WP_Error('db_error', 'Database error. Please contact your system administrator.', ['status' => 500]);
        }

        return [
            'success' => true,
            'user_id' => $user_id
        ];
    }

    /**
     * Return a list of the users.
     *
     * @todo: We need to add a way where the admin can allow which users are chat users.
     */
    public function get_users() {
        global $wpdb;
        $table = $wpdb->prefix . BH_TABLE_USER_KEYS;

        // Get users who have a user_key assigned
        $users = $wpdb->get_results("
            SELECT u.ID, u.display_name, uk.public_key, uk.key_type, uk.expires_at
            FROM {$wpdb->users} u
            INNER JOIN {$table} uk ON u.ID = uk.user_id
            GROUP BY u.ID
        ");

        $user_list = [];
        foreach ($users as $user) {
            $user_list[] = [
                'ID' => (int) $user->ID,
                'display_name' => $user->display_name,
                'public_key' => $user->public_key,
                'key_type' => $user->key_type,
                'expires_at' => $user->expires_at,
            ];
        }
        return $user_list;
    }

    /**
     * Return a list of conversations for the authenticated user.
     *
     * @param WP_REST_Request $request
     * @return array
     */
    public function get_conversations($request) {
        $user_id = $request->get_param('user_id');

        global $wpdb;
        $table = $wpdb->prefix . BH_TABLE_CONVERSATIONS;

        // Get conversations for the user
        $conversations = $wpdb->get_results($wpdb->prepare(
            "SELECT c.* FROM $table c
            JOIN {$wpdb->prefix}" . BH_TABLE_CONVERSATION_MEMBERS . " cm ON c.ID = cm.conversation_id
            WHERE cm.user_id = %d",
            $user_id
        ));

        // For each conversation, get members and their keys
        foreach ($conversations as &$conversation) {
            // Get members
            $members = $wpdb->get_results($wpdb->prepare(
                "SELECT u.ID, u.display_name, uk.public_key, uk.key_type, uk.expires_at
             FROM {$wpdb->prefix}" . BH_TABLE_CONVERSATION_MEMBERS . " cm
             JOIN {$wpdb->prefix}users u ON cm.user_id = u.ID
             LEFT JOIN {$wpdb->prefix}" . BH_TABLE_USER_KEYS . " uk ON uk.user_id = u.ID
             WHERE cm.conversation_id = %d",
                $conversation->ID
            ));

            $conversation->members = $members;
        }

        return $conversations;
    }

    /**
     * Get messages for a specific conversation.
     *
     * @todo: Add pagination to limit the number of messages returned at once.
     *
     * @param WP_REST_Request $request
     * @return array|WP_Error
     */
    public function get_conversation_messages($request) {

        $user_id = $request->get_param('user_id');
        $conversation_id = $request->get_param('conversation_id');

        if (empty($conversation_id) || !is_numeric($conversation_id) || intval($conversation_id) <= 0 || empty($user_id) || !is_numeric($user_id) || intval($user_id) <= 0) {
            return new WP_Error('invalid_request', 'Missing or invalid parameters.', ['status' => 400]);
        }

        global $wpdb;

        // Check if user is a member of the conversation
        $is_member = $wpdb->get_var($wpdb->prepare(
            "SELECT conversation_id FROM {$wpdb->prefix}" . BH_TABLE_CONVERSATION_MEMBERS . " WHERE conversation_id = %d AND user_id = %d",
            $conversation_id,
            $user_id
        ));

        if (!$is_member) {
            return new WP_Error('not_a_member', 'You are not a member of this conversation.', ['status' => 403]);
        }

        // Get messages for the conversation
        $messages = $wpdb->get_results($wpdb->prepare(
            "SELECT m.* FROM {$wpdb->prefix}" . BH_TABLE_MESSAGES . " m
            WHERE m.conversation_id = %d",
            $conversation_id
        ));

        // Get conversation data
        $conversation = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}" . BH_TABLE_CONVERSATIONS . " WHERE ID = %d",
            $conversation_id
        ));

        // Get members and their public keys
        $members = $wpdb->get_results($wpdb->prepare(
            "SELECT u.ID, u.display_name, uk.public_key, uk.key_type, uk.expires_at
             FROM {$wpdb->prefix}" . BH_TABLE_CONVERSATION_MEMBERS . " cm
             JOIN {$wpdb->users} u ON cm.user_id = u.ID
             LEFT JOIN {$wpdb->prefix}" . BH_TABLE_USER_KEYS . " uk ON uk.user_id = u.ID
             WHERE cm.conversation_id = %d",
            $conversation_id
        ));

        return [
            'conversation' => $conversation,
            'members' => $members,
            'messages' => $messages
        ];

        return $messages;
    }

    /**
     * Start a new conversation between two users with an initial encrypted message.
     * 
     * @todo: If there is aready an existing conversation between the two users, send the message there instead of creating a new one.
     *
     * @param WP_REST_Request $request
     * @return array|WP_Error
     */
    public function start_private_conversation($request) {
        $params = $request->get_body_params();
        if (empty($params)) {
            $params = json_decode($request->get_body(), true) ?? [];
        }

        $creator_id = intval($request->get_param('user_id'));
        $other_user_id = intval($params['other_user_id'] ?? 0);
        $encrypted_session_key = sanitize_text_field($params['encrypted_session_key']);

        if (!$creator_id || !$other_user_id) {
            return new WP_Error('invalid_params', 'Missing required parameters.', ['status' => 400]);
        }

        global $wpdb;

        // Insert new conversation
        $insert_conversation = $wpdb->insert(
            $wpdb->prefix . BH_TABLE_CONVERSATIONS,
            [
                'type' => 'private',
                'created_by' => $creator_id,
                'session_key' => $encrypted_session_key
            ]
        );

        if ($insert_conversation === false) {
            return new WP_Error('db_error', 'Failed to create conversation.', ['status' => 500]);
        }

        $conversation_id = $wpdb->insert_id;

        // Add the members to the conversation
        // @todo - Look at a better way to add multiple members to keep the query efficient and clean.
        $members_inserted = $wpdb->insert(
            $wpdb->prefix . BH_TABLE_CONVERSATION_MEMBERS,
            [
                'conversation_id' => $conversation_id,
                'user_id' => $creator_id
            ]
        );
        $members_inserted = $wpdb->insert(
            $wpdb->prefix . BH_TABLE_CONVERSATION_MEMBERS,
            [
                'conversation_id' => $conversation_id,
                'user_id' => $other_user_id
            ]
        );

        // @todo - Clean this up. We need to ensure error handling is correct and efficient.
        //if ($members_inserted === false) {
        //    return new WP_Error('db_error', 'Failed to add members.', ['status' => 500]);
        //}

        // @todo: Return conversation details like the user keys or do we rely on the client to already have everything needed.
        return [
            'success' => true,
            'conversation_id' => $conversation_id
        ];
    }

    /**
     * Start a new group conversation with an initial encrypted message.
     * 
     * @todo Tie this into the rest API hook.
     * 
     * @param WP_REST_Request $request
     * @return array|WP_Error
     */
    public function start_group_conversation($request) {
        $params = $request->get_body_params();
        if (empty($params)) {
            $params = json_decode($request->get_body(), true) ?? [];
        }
        $creator_id = intval($request->get_param('user_id'));

        // @todo: I am not sure this is the best way to do this. Maybe support JSON body? JSON would not be inline with form data we are using for other things.
        $member_ids = [];
        if (isset($params['member_ids'])) {
            if (is_array($params['member_ids'])) {
                $member_ids = array_map('intval', $params['member_ids']);
            } elseif (is_string($params['member_ids'])) {
                $member_ids = array_map('intval', array_filter(array_map('trim', explode(',', $params['member_ids']))));
            }
        }
        $encrypted_message = sanitize_text_field($params['encrypted_message'] ?? '');

        // Ensure creator is included and remove duplicates.
        $all_member_ids = array_unique(array_merge([$creator_id], $member_ids));

        // @todo: Maybe look into simply making a single group if this fails to be 2 or more members.
        if (!$creator_id || count($all_member_ids) < 2 || empty($encrypted_message)) {
            return new WP_Error('invalid_params', 'Missing required parameters.', ['status' => 400]);
        }

        global $wpdb;

        // Insert new group conversation
        $insert_conversation = $wpdb->insert(
            $wpdb->prefix . BH_TABLE_CONVERSATIONS,
            [
                'type' => 'group',
                'created_by' => $creator_id
            ]
        );

        if ($insert_conversation === false) {
            return new WP_Error('db_error', 'Failed to create group conversation.', ['status' => 500]);
        }

        $conversation_id = $wpdb->insert_id;

        // Prepare values for bulk insert
        $values = [];
        foreach ($all_member_ids as $user_id) {
            $values[] = $wpdb->prepare('(%d, %d)', $conversation_id, $user_id);
        }
        $values_sql = implode(',', $values);

        $members_inserted = $wpdb->query(
            "INSERT INTO {$wpdb->prefix}" . BH_TABLE_CONVERSATION_MEMBERS . " (conversation_id, user_id) VALUES $values_sql"
        );

        if ($members_inserted === false) {
            return new WP_Error('db_error', 'Failed to add group members.', ['status' => 500]);
        }

        // Insert first group message
        $message_inserted = $wpdb->insert(
            $wpdb->prefix . BH_TABLE_MESSAGES,
            [
                'conversation_id' => $conversation_id,
                'sender_id' => $creator_id,
                'encrypted_text' => $encrypted_message
            ]
        );

        if ($message_inserted === false) {
            return new WP_Error('db_error', 'Failed to send group message.', ['status' => 500]);
        }

        return [
            'success' => true,
            'conversation_id' => $conversation_id
        ];
    }

    /**
     * Send a message in a conversation.
     * This can send a message to either a private or group conversation. It is indifferent.
     * 
     * @param WP_REST_Request $request
     * @return array|WP_Error
     */
    public function send_message($request) {
        $params = $request->get_body_params();
        if (empty($params)) {
            $params = json_decode($request->get_body(), true) ?? [];
        }

        $conversation_id = intval($request->get_param('conversation_id')); // Grab the conversation from the url
        $sender_id = intval($request->get_param('user_id'));
        $message = sanitize_text_field($params['message'] ?? '');
        $nonce = sanitize_text_field($params['nonce'] ?? '');

        if (!$conversation_id || !$sender_id || empty($message) || empty($nonce)) {
            return new WP_Error('invalid_params', 'Missing required parameters.', ['status' => 400]);
        }

        global $wpdb;

        // Be sure the sender is part of the conversation.
        $is_member = $wpdb->get_var($wpdb->prepare(
            "SELECT conversation_id FROM {$wpdb->prefix}" . BH_TABLE_CONVERSATION_MEMBERS . " WHERE conversation_id = %d AND user_id = %d",
            $conversation_id,
            $sender_id
        ));

        if (!$is_member) {

            // This is most likely and unauthorized access attempt.
            do_action('blackhaven_messenger_unauthorized_conversation_access_attempt', [
                'conversation_id' => $conversation_id,
                'user_id' => $sender_id,
                'request_ip' => $_SERVER['REMOTE_ADDR'] ?? '',
                'request_data' => $params,
            ]);

            return new WP_Error('not_a_member', 'You are not a member of this conversation.', ['status' => 403]);
        }

        // Insert the new message.
        $message_inserted = $wpdb->insert(
            $wpdb->prefix . BH_TABLE_MESSAGES,
            [
                'conversation_id' => $conversation_id,
                'sender_id' => $sender_id,
                'message_text' => $message,
                'nonce' => $nonce
            ]
        );

        if ($message_inserted === false) {
            return new WP_Error('db_error', 'Failed to send message.', ['status' => 500]);
        }

        return [
            'success' => true,
            'message_id' => $wpdb->insert_id
        ];
    }

    public function edit_message($request) {
    }

    public function recall_message($request) {
    }

    public function leave_conversation($request) {
    }
}
