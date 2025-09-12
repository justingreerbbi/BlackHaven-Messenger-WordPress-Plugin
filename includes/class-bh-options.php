<?php
if (! defined('ABSPATH')) exit;

/**
 * BH_Messenger_Options
 *
 * Owns the Messenger Settings admin page with tabs (Basic / Advanced / Info)
 * and registers settings/fields via the Settings API.
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
    }

    /* -----------------------------
     * Menu & Pages
     * ---------------------------*/
    public function add_admin_menu() {
        // Main settings page
        add_menu_page(
            'Messenger Settings',
            'Messenger',
            'manage_options',
            $this->menu_slug,
            array($this, 'render_settings_page'),
            'dashicons-admin-generic',
            65
        );

        // New Connection Info submenu
        add_submenu_page(
            $this->menu_slug,
            'Connection Information',
            'Connection Info',
            'manage_options',
            $this->submenu_conn,
            array($this, 'render_connection_page')
        );
    }

    public function render_settings_page() {

        // Restrict access to admins that have the right capability.
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'blackhaven-messenger'));
        }

        $tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'basic';
        ?>
        <div class="wrap">
            <h1>BlackHaven Messenger Settings</h1>

            <?php settings_errors(); ?>

            <p>Configure the BlackHaven Messenger plugin below. Select a tab to view different settings.</p>

            <h2 class="nav-tab-wrapper">
                <a href="<?php echo esc_url(admin_url('admin.php?page=' . $this->menu_slug . '&tab=basic')); ?>"
                    class="nav-tab <?php echo $tab === 'basic' ? 'nav-tab-active' : ''; ?>">Basic</a>

                <a href="<?php echo esc_url(admin_url('admin.php?page=' . $this->menu_slug . '&tab=advanced')); ?>"
                    class="nav-tab <?php echo $tab === 'advanced' ? 'nav-tab-active' : ''; ?>">Advanced</a>

                <a href="<?php echo esc_url(admin_url('admin.php?page=' . $this->menu_slug . '&tab=info')); ?>"
                    class="nav-tab <?php echo $tab === 'info' ? 'nav-tab-active' : ''; ?>">Info</a>
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
                    // Info tab
                    global $wp_version;
                    $theme = wp_get_theme();
                    $active_plugins = get_option('active_plugins', array());
                    $plugins_info = array();

                    foreach ($active_plugins as $plugin_file) {
                        if (file_exists(WP_PLUGIN_DIR . '/' . $plugin_file)) {
                            $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin_file);
                            $plugins_info[] = array(
                                'Name'    => $plugin_data['Name'],
                                'Version' => $plugin_data['Version'],
                                'Author'  => wp_strip_all_tags($plugin_data['Author']),
                                'Plugin'  => $plugin_file,
                            );
                        }
                    }

                    $php_version     = phpversion();
                    $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown';
                ?>
                    <div style="background:#f9f9f9; border:1px solid #e1e1e1; border-radius:4px; padding:1em; position:relative; margin-top:1em;">
                        <button type="button" id="bh-copy-sysinfo" style="position:absolute; top:1em; right:1em; background:#fff; border:1px solid #ccc; border-radius:3px; padding:4px 10px; cursor:pointer; font-size:13px;">Copy</button>
                        <pre id="bh-sysinfo" style="background:none; border:none; margin-left:0; margin-top:0; margin-bottom:15px; font-size:12px; line-height:1.6; color:#222; white-space:pre-wrap;">
                            <?php
                            echo "\n";
                            echo "WordPress Version: {$wp_version}\n";
                            echo "Site URL: " . get_site_url() . "\n";
                            echo "Home URL: " . get_home_url() . "\n";
                            echo "PHP Version: {$php_version}\n";
                            echo "Server Software: {$server_software}\n";
                            echo "Active Theme: " . $theme->get('Name') . "\n";
                            echo "  Version: " . $theme->get('Version') . "\n";
                            echo "  Author: " . $theme->get('Author') . "\n";
                            echo "Active Plugins:\n";
                            foreach ($plugins_info as $plugin) {
                                echo "  - {$plugin['Name']} (v{$plugin['Version']}) by {$plugin['Author']} [{$plugin['Plugin']}]\n";
                            }
                            echo "Inactive Plugins:\n";
                            $all_plugins = get_plugins();
                            foreach ($all_plugins as $plugin_file => $plugin_data) {
                                if (! in_array($plugin_file, $active_plugins)) {
                                    echo "  - {$plugin_data['Name']} (v{$plugin_data['Version']}) by " . wp_strip_all_tags($plugin_data['Author']) . " [{$plugin_file}]\n";
                                }
                            }
                            ?></pre>
                    </div>
                    <script>
                        document.addEventListener('DOMContentLoaded', function() {
                            var btn = document.getElementById('bh-copy-sysinfo');
                            var pre = document.getElementById('bh-sysinfo');
                            btn.addEventListener('click', function() {
                                var text = pre.textContent;
                                navigator.clipboard.writeText(text).then(function() {
                                    btn.textContent = 'Copied!';
                                    setTimeout(function() {
                                        btn.textContent = 'Copy';
                                    }, 1200);
                                });
                            });
                        });
                    </script>
                <?php } ?>
            </form>
        </div>
    <?php
    }

    /* -----------------------------
     * Connection Info Page
     * ---------------------------*/
    public function render_connection_page() {
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'blackhaven-messenger'));
        }

        // Get server URL from settings (fallback to site_url)
        $server_url = get_option($this->opt_server_url, get_site_url() . '/wp-json/blackhaven/v1/messenger');

        $connection_data = array(
            'server'  => esc_url_raw($server_url),
            'app'     => 'BlackHaven Messenger',
            'version' => '1.0.0',
        );
        $json_data = wp_json_encode($connection_data);
    ?>
        <div class="wrap">
            <h1>Connection Information</h1>
            <p>Scan this QR code in the mobile app to connect:</p>

            <div id="bh-qr-code"></div>
            <p><strong>Server URL:</strong> <?php echo esc_html($server_url); ?></p>
            <p><strong>Raw JSON:</strong> <code><?php echo esc_html($json_data); ?></code></p>
        </div>

        <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"
            integrity="sha512-8zF6ffXh1kY2hKkkYDj0N8i1Pv6xr91p+5dO6L5v1jzBc6VdUq3X5rRBlqKftvSmH9T+7BQ5S0sjRJz3jR+ZCg=="
            crossorigin="anonymous" referrerpolicy="no-referrer"></script>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                new QRCode(document.getElementById("bh-qr-code"), {
                    text: <?php echo wp_json_encode($json_data); ?>,
                    width: 200,
                    height: 200,
                    colorDark: "#000000",
                    colorLight: "#ffffff",
                    correctLevel: QRCode.CorrectLevel.H
                });
            });
        </script>
    <?php
    }

    /* -----------------------------
     * Settings API Registration
     * ---------------------------*/
    public function register_settings() {
        // BASIC TAB
        register_setting($this->group_basic, $this->opt_basic); // will now be an array
        add_settings_section('bh_messenger_section_basic', 'Basic Settings', '__return_false', $this->screen_basic);
        
        add_settings_field('bh_messenger_feature', 'API Enabled', [$this, 'render_api_enabled_option'], $this->screen_basic, 'bh_messenger_section_basic');
        add_settings_field('bh_messenger_api_key', 'API Key', [$this, 'render_basic_api_key'], $this->screen_basic, 'bh_messenger_section_basic');

        // ADVANCED TAB
        register_setting($this->group_advanced, $this->opt_advanced); // also array
        add_settings_section('bh_messenger_section_advanced', 'Advanced Settings', '__return_false', $this->screen_advanced);
        add_settings_field('bh_messenger_timeout', 'Timeout', [$this, 'render_advanced_timeout'], $this->screen_advanced, 'bh_messenger_section_advanced');
        add_settings_field('bh_messenger_debug', 'Enable Debug Mode', [$this, 'render_advanced_debug'], $this->screen_advanced, 'bh_messenger_section_advanced');

        // CONNECTION PAGE
        register_setting('bh_messenger_connection', $this->opt_server_url);
    }

    /* -----------------------------
     * Field Renderers
     * ---------------------------*/

    // BASIC
    public function render_basic_api_key() {
        $options = get_option($this->opt_basic, []);
        $value = isset($options['api_key']) ? $options['api_key'] : '';
        ?>
        <input type="text" name="<?php echo esc_attr($this->opt_basic); ?>[api_key]"
            value="<?php echo esc_attr($value); ?>" class="regular-text" />
        <?php
    }

    public function render_api_enabled_option() {
        $options = get_option($this->opt_basic, []);
        $checked = !empty($options['feature']) ? 'checked' : '';
        ?>
        <label>
            <input type="checkbox" name="<?php echo esc_attr($this->opt_basic); ?>[feature]" value="1" <?php echo $checked; ?> />
        </label>
        <?php
    }

    // ADVANCED
    public function render_advanced_timeout() {
        $options = get_option($this->opt_advanced, []);
        $value = isset($options['timeout']) ? intval($options['timeout']) : 30;
        ?>
        <input type="number" name="<?php echo esc_attr($this->opt_advanced); ?>[timeout]"
            value="<?php echo esc_attr($value); ?>" min="1" /> seconds
        <?php
    }

    public function render_advanced_debug() {
        $options = get_option($this->opt_advanced, []);
        $checked = !empty($options['debug']) ? 'checked' : '';
        ?>
        <label>
            <input type="checkbox" name="<?php echo esc_attr($this->opt_advanced); ?>[debug]" value="1" <?php echo $checked; ?> />
            Enable Debug Mode
        </label>
        <?php
    }

}
