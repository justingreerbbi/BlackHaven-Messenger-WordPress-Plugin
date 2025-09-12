<?php
if (! defined('ABSPATH')) exit;

/**
 * BH_Messenger_Options
 */
class BH_Messenger_Options {

    /** Slugs & option names */
    private $menu_slug        = 'blackhaven-messenger';
    private $submenu_conn     = 'blackhaven-messenger-connection';
    private $group_basic      = 'bh_messenger_basic';
    private $group_advanced   = 'bh_messenger_advanced';
    private $screen_basic     = 'blackhaven-messenger-basic';
    private $screen_advanced  = 'blackhaven-messenger-advanced';
    private $opt_basic        = 'bh_messenger_option';
    private $opt_advanced     = 'bh_messenger_advanced_options';
    private $opt_server_url   = 'bh_messenger_server_url';

    public function __construct() {
        add_action('admin_menu',  array($this, 'add_admin_menu'), 10);
        add_action('admin_init',  array($this, 'register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
    }

    /* -----------------------------
     * Enqueue QR Script
     * ---------------------------*/
    public function enqueue_assets($hook) {
        if (strpos($hook, $this->menu_slug) === false) {
            return;
        }

        wp_enqueue_script(
            'bh-qr',
            'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js',
            [],
            '1.0.0',
            true
        );
    }

    /* -----------------------------
     * Menu & Pages
     * ---------------------------*/
    public function add_admin_menu() {
        add_menu_page(
            __('Messenger Settings', 'blackhaven-messenger'),
            __('Messenger', 'blackhaven-messenger'),
            'manage_options',
            $this->menu_slug,
            array($this, 'render_settings_page'),
            'dashicons-email',
            1000
        );

        add_submenu_page(
            $this->menu_slug,
            __('Messenger Settings', 'blackhaven-messenger'),
            __('Settings', 'blackhaven-messenger'),
            'manage_options',
            $this->menu_slug,
            array($this, 'render_settings_page')
        );

        add_submenu_page(
            $this->menu_slug,
            __('Connection Information', 'blackhaven-messenger'),
            __('Connection Info', 'blackhaven-messenger'),
            'manage_options',
            $this->submenu_conn,
            array($this, 'render_connection_page')
        );
    }

    public function render_settings_page() {
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'blackhaven-messenger'));
        }

        $tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'basic';
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('BlackHaven Messenger Settings', 'blackhaven-messenger'); ?></h1>

            <?php settings_errors(); ?>

            <h2 class="nav-tab-wrapper">
                <a href="<?php echo esc_url(admin_url('admin.php?page=' . $this->menu_slug . '&tab=basic')); ?>"
                   class="nav-tab <?php echo $tab === 'basic' ? 'nav-tab-active' : ''; ?>">
                   <?php esc_html_e('Basic', 'blackhaven-messenger'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=' . $this->menu_slug . '&tab=advanced')); ?>"
                   class="nav-tab <?php echo $tab === 'advanced' ? 'nav-tab-active' : ''; ?>">
                   <?php esc_html_e('Advanced', 'blackhaven-messenger'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=' . $this->menu_slug . '&tab=info')); ?>"
                   class="nav-tab <?php echo $tab === 'info' ? 'nav-tab-active' : ''; ?>">
                   <?php esc_html_e('Info', 'blackhaven-messenger'); ?>
                </a>
            </h2>

            <form method="post" action="options.php">
                <?php
                if ($tab === 'basic') {
                    settings_fields($this->group_basic);
                    do_settings_sections($this->screen_basic);
                    submit_button();
                } elseif ($tab === 'advanced') {
                    settings_fields($this->group_advanced);
                    do_settings_sections($this->screen_advanced);
                    submit_button();
                } else {
                    $this->render_info_tab();
                }
                ?>
            </form>
        </div>
        <?php
    }

    /* -----------------------------
     * Info Tab (full system info)
     * ---------------------------*/
    private function render_info_tab() {
        global $wp_version;
        $theme          = wp_get_theme();
        $php_version    = phpversion();
        $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown';

        $active_plugins = get_option('active_plugins', []);
        $plugins_info   = [];

        foreach ($active_plugins as $plugin_file) {
            if (file_exists(WP_PLUGIN_DIR . '/' . $plugin_file)) {
                $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin_file);
                $plugins_info[] = [
                    'Name'    => $plugin_data['Name'],
                    'Version' => $plugin_data['Version'],
                    'Author'  => wp_strip_all_tags($plugin_data['Author']),
                    'Plugin'  => $plugin_file,
                ];
            }
        }

        $all_plugins = get_plugins();
        ?>
        <div style="background:#f9f9f9; border:1px solid #e1e1e1; border-radius:4px; padding:1em; position:relative; margin-top:1em;">
            <button type="button" id="bh-copy-sysinfo" style="position:absolute; top:1em; right:1em; background:#fff; border:1px solid #ccc; border-radius:3px; padding:4px 10px; cursor:pointer; font-size:13px;">
                <?php esc_html_e('Copy', 'blackhaven-messenger'); ?>
            </button>
            <pre id="bh-sysinfo" style="background:none; border:none; margin-left:0; margin-top:0; margin-bottom:15px; font-size:12px; line-height:1.6; color:#222; white-space:pre-wrap;">
<?php
echo "WordPress Version: {$wp_version}\n";
echo "Site URL: " . esc_url(get_site_url()) . "\n";
echo "Home URL: " . esc_url(get_home_url()) . "\n";
echo "PHP Version: {$php_version}\n";
echo "Server Software: {$server_software}\n";
echo "Active Theme: " . esc_html($theme->get('Name')) . "\n";
echo "  Version: " . esc_html($theme->get('Version')) . "\n";
echo "  Author: " . esc_html($theme->get('Author')) . "\n";

echo "Active Plugins:\n";
foreach ($plugins_info as $plugin) {
    echo "  - " . esc_html($plugin['Name']) . " (v" . esc_html($plugin['Version']) . ") by " . esc_html($plugin['Author']) . " [" . esc_html($plugin['Plugin']) . "]\n";
}

echo "Inactive Plugins:\n";
foreach ($all_plugins as $plugin_file => $plugin_data) {
    if (! in_array($plugin_file, $active_plugins, true)) {
        echo "  - " . esc_html($plugin_data['Name']) . " (v" . esc_html($plugin_data['Version']) . ") by " . esc_html(wp_strip_all_tags($plugin_data['Author'])) . " [" . esc_html($plugin_file) . "]\n";
    }
}
?>
            </pre>
        </div>
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var btn = document.getElementById('bh-copy-sysinfo');
            var pre = document.getElementById('bh-sysinfo');
            btn.addEventListener('click', function() {
                navigator.clipboard.writeText(pre.textContent).then(function() {
                    btn.textContent = '<?php echo esc_js(__('Copied!', 'blackhaven-messenger')); ?>';
                    setTimeout(function() {
                        btn.textContent = '<?php echo esc_js(__('Copy', 'blackhaven-messenger')); ?>';
                    }, 1200);
                });
            });
        });
        </script>
        <?php
    }

    /* -----------------------------
     * Connection Info Page
     * ---------------------------*/
    public function render_connection_page() {
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'blackhaven-messenger'));
        }

        $server_url = get_option($this->opt_server_url, get_site_url() . '/wp-json/blackhaven/v1/messenger');
        $connection_data = [
            'server'  => esc_url_raw($server_url),
            'app'     => 'BlackHaven Messenger',
            'version' => '1.0.0',
        ];
        $json_data = wp_json_encode($connection_data);
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('Connection Information', 'blackhaven-messenger'); ?></h1>
            <p><?php esc_html_e('Scan this QR code in the mobile app to connect:', 'blackhaven-messenger'); ?></p>

            <div id="bh-qr-code"></div>
            <p><strong><?php esc_html_e('Server URL:', 'blackhaven-messenger'); ?></strong>
                <?php echo esc_html($server_url); ?></p>
            <p><strong><?php esc_html_e('Raw JSON:', 'blackhaven-messenger'); ?></strong>
                <code><?php echo esc_html($json_data); ?></code></p>
        </div>

        <script>
        document.addEventListener('DOMContentLoaded', function() {
            if (typeof QRCode !== 'undefined') {
                new QRCode(document.getElementById("bh-qr-code"), {
                    text: <?php echo wp_json_encode($json_data); ?>,
                    width: 200,
                    height: 200,
                    colorDark: "#000000",
                    colorLight: "#ffffff",
                    correctLevel: QRCode.CorrectLevel.H
                });
            }
        });
        </script>
        <?php
    }

    /* -----------------------------
     * Settings Registration
     * ---------------------------*/
    public function register_settings() {
        register_setting(
            $this->group_basic,
            $this->opt_basic,
            ['sanitize_callback' => [$this, 'sanitize_basic_options']]
        );
        add_settings_section('bh_messenger_section_basic', __('Basic Settings', 'blackhaven-messenger'), '__return_false', $this->screen_basic);
        add_settings_field('bh_messenger_feature', __('API Enabled', 'blackhaven-messenger'), [$this, 'render_api_enabled_option'], $this->screen_basic, 'bh_messenger_section_basic');

        register_setting(
            $this->group_advanced,
            $this->opt_advanced,
            ['sanitize_callback' => [$this, 'sanitize_advanced_options']]
        );
        add_settings_section('bh_messenger_section_advanced', __('Advanced Settings', 'blackhaven-messenger'), '__return_false', $this->screen_advanced);
        add_settings_field('bh_messenger_access_token_lifetime', __('Access Token Lifetime', 'blackhaven-messenger'), [$this, 'render_advanced_access_token_lifetime'], $this->screen_advanced, 'bh_messenger_section_advanced');
        add_settings_field('bh_messenger_remove_data_on_deactivation', __('Remove Data on Deactivation', 'blackhaven-messenger'), [$this, 'render_advanced_remove_data_on_deactivation'], $this->screen_advanced, 'bh_messenger_section_advanced');
        add_settings_field('bh_messenger_debug', __('Enable Debug Mode', 'blackhaven-messenger'), [$this, 'render_advanced_debug'], $this->screen_advanced, 'bh_messenger_section_advanced');

        register_setting(
            'bh_messenger_connection',
            $this->opt_server_url,
            ['sanitize_callback' => 'esc_url_raw']
        );
    }

    /* -----------------------------
     * Sanitization
     * ---------------------------*/
    public function sanitize_basic_options($input) {
        return ['enable_api' => !empty($input['enable_api']) ? 1 : 0];
    }

    public function sanitize_advanced_options($input) {
        return [
            'access_token_lifetime'     => isset($input['access_token_lifetime']) ? max(5, absint($input['access_token_lifetime'])) : 30,
            'remove_data_on_deactivation' => !empty($input['remove_data_on_deactivation']) ? 1 : 0,
            'debug'                     => !empty($input['debug']) ? 1 : 0,
        ];
    }

    /* -----------------------------
     * Field Renderers
     * ---------------------------*/
    public function render_api_enabled_option() {
        $options = get_option($this->opt_basic, []);
        $checked = !empty($options['enable_api']) ? 'checked' : '';
        ?>
        <label>
            <input type="checkbox" name="<?php echo esc_attr($this->opt_basic); ?>[enable_api]" value="1" <?php echo $checked; ?> />
            <?php esc_html_e('Enable API access', 'blackhaven-messenger'); ?>
        </label>
        <?php
    }

    public function render_advanced_access_token_lifetime() {
        $options = get_option($this->opt_advanced, []);
        $value = isset($options['access_token_lifetime']) ? intval($options['access_token_lifetime']) : 30;
        ?>
        <input type="number"
               name="<?php echo esc_attr($this->opt_advanced); ?>[access_token_lifetime]"
               value="<?php echo esc_attr($value); ?>"
               min="5" /> <?php esc_html_e('seconds (minimum 5)', 'blackhaven-messenger'); ?>
        <?php
    }

    public function render_advanced_remove_data_on_deactivation() {
        $options = get_option($this->opt_advanced, []);
        $checked = !empty($options['remove_data_on_deactivation']) ? 'checked' : '';
        ?>
        <label>
            <input type="checkbox" name="<?php echo esc_attr($this->opt_advanced); ?>[remove_data_on_deactivation]" value="1" <?php echo $checked; ?> />
            <?php esc_html_e('Remove all plugin data on deactivation (including access tokens)', 'blackhaven-messenger'); ?>
        </label>
        <?php
    }

    public function render_advanced_debug() {
        $options = get_option($this->opt_advanced, []);
        $checked = !empty($options['debug']) ? 'checked' : '';
        ?>
        <label>
            <input type="checkbox" name="<?php echo esc_attr($this->opt_advanced); ?>[debug]" value="1" <?php echo $checked; ?> />
            <?php esc_html_e('Enable Debug Mode', 'blackhaven-messenger'); ?>
        </label>
        <?php
    }
}
