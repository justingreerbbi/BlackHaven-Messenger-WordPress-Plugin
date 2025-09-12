<?php
if (! defined('ABSPATH')) exit;

/**
 * BH_Messenger_Security_Audit
 *
 * Runs hosted-friendly security checks and renders an admin report.
 */
class BH_Security_Audit {

    private $menu_parent_slug = 'blackhaven-messenger'; // parent menu slug you already use
    private $menu_slug        = 'bhm-security-audit';
    private $transient_key    = 'bhm_last_security_audit';
    private $nonce_action     = 'bhm_run_audit';
    private $cache_ttl        = 1800; // 30 min

    public function __construct() {
        add_action('admin_menu', [$this, 'add_submenu'], 20);
        add_action('admin_post_bhm_run_audit', [$this, 'handle_run_audit']);
    }

    public function add_submenu() {
        add_submenu_page(
            $this->menu_parent_slug,
            'Security Audit',
            'Security Audit',
            'manage_options',
            $this->menu_slug,
            [$this, 'render_page']
        );
    }

    public function handle_run_audit() {
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to run this scan.', 'blackhaven-messenger'));
        }
        check_admin_referer($this->nonce_action);

        $result = $this->run_scan();
        set_transient($this->transient_key, $result, $this->cache_ttl);

        wp_safe_redirect(add_query_arg(['page' => $this->menu_slug, 'ran' => 1], admin_url('admin.php')));
        exit;
    }

    public function render_page() {
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to view this page.', 'blackhaven-messenger'));
        }

        $result = get_transient($this->transient_key);
?>
        <div class="wrap">
            <h1>Security Audit</h1>
            <p>This automated check highlights common WordPress & hosting misconfigurations that can increase risk—
                especially on shared hosts. It’s not a penetration test, but it covers many industry “first-pass” checks.</p>

            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin: 1em 0;">
                <?php wp_nonce_field($this->nonce_action); ?>
                <input type="hidden" name="action" value="bhm_run_audit" />
                <?php submit_button('Run Scan Now', 'primary', 'submit', false); ?>
                <?php if ($result) : ?>
                    <span style="margin-left:10px;color:#666;">Last run: <?php echo esc_html($result['summary']['when'] ?? ''); ?></span>
                <?php endif; ?>
            </form>

            <?php
            if (! $result) {
                echo '<div class="notice notice-info"><p>No cached results yet. Click <em>Run Scan Now</em> above.</p></div>';
                return;
            }

            $totals = $result['summary']['totals'];
            $badge  = function ($status) {
                $map = [
                    'pass' => ['#1e8e3e', 'PASS'],
                    'warn' => ['#dba617', 'WARN'],
                    'fail' => ['#d63638', 'FAIL'],
                    'info' => ['#2271b1', 'INFO'],
                ];
                $m = $map[$status] ?? $map['info'];
                return '<span style="display:inline-block;padding:.15em .5em;border-radius:3px;background:' . $m[0] . ';color:#fff;font-weight:600;">' . $m[1] . '</span>';
            };
            ?>

            <h2>Summary</h2>
            <ul style="display:flex;gap:20px;padding-left:0;list-style:none;">
                <li><?php echo $badge('pass'); ?> <?php echo (int) $totals['pass']; ?></li>
                <li><?php echo $badge('warn'); ?> <?php echo (int) $totals['warn']; ?></li>
                <li><?php echo $badge('fail'); ?> <?php echo (int) $totals['fail']; ?></li>
                <li><?php echo $badge('info'); ?> <?php echo (int) $totals['info']; ?></li>
            </ul>

            <h2>Detailed Checks</h2>
            <table class="widefat striped">
                <thead>
                    <tr>
                        <th style="width:160px;">Check</th>
                        <th style="width:80px;">Status</th>
                        <th>Details</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($result['checks'] as $check) : ?>
                        <tr>
                            <td><strong><?php echo esc_html($check['label']); ?></strong></td>
                            <td><?php echo $badge($check['status']); ?></td>
                            <td><?php echo wp_kses_post($check['details']); ?></td>
                            <td><?php echo wp_kses_post($check['recommendation']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
<?php
    }

    /* =========================
     * Scanner implementation
     * ========================= */
    private function run_scan() {
        $checks = [];

        $add = function ($label, $status, $details, $recommendation) use (&$checks) {
            $checks[] = [
                'label'          => $label,
                'status'         => $status,        // pass|warn|fail|info
                'details'        => $details,
                'recommendation' => $recommendation,
                'fix_function'   => null, // optional callable to fix (if feasible)
            ];
        };

        // --- Plugin-specific checks ---
        $this->check_plugin_restrictions_htaccess($add);

        // --- HTTPS / SSL ---
        $this->check_https($add);
        $this->check_security_headers($add);

        // --- Exposure tests ---
        $this->check_directory_indexing($add);
        $this->check_sensitive_files($add);

        // --- PHP runtime / ini ---
        $this->check_php_version($add);
        $this->check_php_ini($add);

        // --- Database / WP config ---
        $this->check_db_version_and_modes($add);
        $this->check_table_prefix($add);
        $this->check_auth_salts($add);

        // --- WP hardening ---
        $this->check_wp_debug_and_editor($add);
        $this->check_updates($add);
        $this->check_xmlrpc($add);
        $this->check_admin_user_and_author_enum($add);
        $this->check_file_permissions($add);

        // Totals
        $totals = ['pass' => 0, 'warn' => 0, 'fail' => 0, 'info' => 0];
        foreach ($checks as $c) {
            $totals[$c['status']]++;
        }

        return [
            'summary' => [
                'when'   => current_time('mysql'),
                'totals' => $totals,
            ],
            'checks'  => $checks,
        ];
    }

    /* ========== Individual checks ========== */

    private function check_plugin_restrictions_htaccess($add) {
        // This is a placeholder for a potential future check.
        // Implementing this would require reading .htaccess or server config,
        // which may not be feasible in all hosting environments.
        $htaccess_path = ABSPATH . '.htaccess';
        if (!file_exists($htaccess_path) || !is_readable($htaccess_path)) {
            $add(
                '.htaccess plugin protection',
                'info',
                'Could not read .htaccess file.',
                'Ensure your .htaccess is readable and restrict direct access to plugin files if possible.'
            );
            return;
        }

        $htaccess_content = file_get_contents($htaccess_path);
        $plugin_dir = basename(dirname(__DIR__));
        $rule_found = false;

        // Look for a RewriteRule that matches the plugin directory and returns a 404
        $pattern = '/RewriteRule\s+\^wp-content\/plugins\/' . preg_quote($plugin_dir, '/') . '\/.*\s+-\s*\[R\s*=\s*404[^\]]*\]/i';
        if (preg_match($pattern, $htaccess_content)) {
            $rule_found = true;
        }

        if ($rule_found) {
            $add(
                'Direct plugin access',
                'pass',
                'Awesome! Found a RewriteRule that blocks direct access to plugin files with a 404. This prevents direct access and adds another layer of security for attackers directly looking for BlackHaven Messenger on your system.',
                'Direct access to BlackHaven Messenger files is blocked.'
            );
        } else {
            $add(
                'Direct plugin access',
                'warn',
                'No RewriteRule found to block direct access to plugin files. While this is not a critical issue, adding such a rule can enhance security by preventing direct access to plugin files. It will also help hide the BlackHaven Messenger plugin from outsiders probing publicly available plugin files.',
                'Add a rule to your .htaccess to block direct access: <br><code>RewriteRule ^wp-content/plugins/' . esc_html($plugin_dir) . '/.* - [R=404]</code>'
            );
        }
    }

    private function check_https($add) {
        $home = home_url();
        $site = site_url();
        $is_ssl = is_ssl();
        $https_urls = (0 === strpos($home, 'https://')) && (0 === strpos($site, 'https://'));

        // Try forcing HTTP to see if it redirects to HTTPS
        $http_home = preg_replace('#^https://#', 'http://', $home);
        $resp = $this->http_head_or_get($http_home);
        $redir_to_https = $resp['is_redirect'] && !empty($resp['location']) && 0 === strpos($resp['location'], 'https://');

        if ($https_urls && ($is_ssl || $redir_to_https)) {
            $add(
                'HTTPS enforced',
                'pass',
                'Site URLs use HTTPS and HTTP traffic redirects to HTTPS.',
                'Keep HTTPS enforced. Consider HSTS for strict transport (see Security Headers check).'
            );
        } else {
            $add(
                'HTTPS enforced',
                'fail',
                'Either site URLs are not HTTPS or HTTP is not redirected to HTTPS.',
                'Set both <code>home</code> and <code>siteurl</code> to <code>https://</code> and configure a 301 redirect from HTTP to HTTPS (web server or security plugin).'
            );
        }
    }

    private function check_security_headers($add) {
        $resp = $this->http_head_or_get(home_url());
        $h = $resp['headers'];

        $have = function ($key) use ($h) {
            return isset($h[$key]);
        };

        $missing = [];
        $ok = 0;

        $pairs = [
            'strict-transport-security' => 'HSTS',
            'x-frame-options'           => 'X-Frame-Options',
            'x-content-type-options'    => 'X-Content-Type-Options',
            'referrer-policy'           => 'Referrer-Policy',
            'content-security-policy'   => 'Content-Security-Policy',
            'permissions-policy'        => 'Permissions-Policy',
        ];
        foreach ($pairs as $k => $label) {
            if ($have($k)) $ok++;
            else $missing[] = $label;
        }

        if ($ok >= 4) {
            $add(
                'HTTP security headers',
                'warn',
                'Some key headers present; missing: ' . esc_html(implode(', ', $missing)),
                'Add the missing headers at the web server or via a security plugin. At minimum: HSTS (for HTTPS sites), X-Frame-Options, X-Content-Type-Options, Referrer-Policy.'
            );
        } else {
            $add(
                'HTTP security headers',
                'fail',
                'Most recommended security headers are missing.',
                'Add HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and ideally CSP & Permissions-Policy.'
            );
        }
    }

    private function check_directory_indexing($add) {
        $targets = [];

        // uploads base
        $up = wp_upload_dir();
        if (! empty($up['baseurl'])) {
            $targets['Uploads directory'] = trailingslashit($up['baseurl']);
        }

        // wp-content
        if (defined('WP_CONTENT_URL')) {
            $targets['wp-content directory'] = trailingslashit(WP_CONTENT_URL);
        } else {
            $targets['wp-content directory'] = trailingslashit(content_url());
        }

        $exposed = [];
        foreach ($targets as $label => $url) {
            $r = $this->http_get($url);
            if ($r['status'] === 200 && is_string($r['body']) && preg_match('/<title>\s*Index of/i', $r['body'])) {
                $exposed[] = $label;
            }
        }

        if (empty($exposed)) {
            $add(
                'Directory listing',
                'pass',
                'Common public directories do not expose listings.',
                'Keep directory indexes disabled (e.g., <code>Options -Indexes</code> for Apache).'
            );
        } else {
            $add(
                'Directory listing',
                'fail',
                'The following appear to list files: ' . esc_html(implode(', ', $exposed)),
                'Disable directory indexes in your web server config or via an .htaccess rule (<code>Options -Indexes</code>).'
            );
        }
    }

    private function check_sensitive_files($add) {
        $base = home_url('/');
        $paths = [
            '.env',
            '.git/config',
            'readme.html',
            'phpinfo.php',
            // wp-config.php should not be readable via web even if moved
            'wp-config.php',
        ];
        $exposed = [];
        foreach ($paths as $p) {
            $r = $this->http_head_or_get($base . $p);
            if ($r['status'] === 200) {
                $exposed[] = $p;
            }
        }
        if (empty($exposed)) {
            $add(
                'Sensitive files exposure',
                'pass',
                'No sensitive files appear publicly accessible.',
                'Keep web root clean and block access to dotfiles and config files at the web server.'
            );
        } else {
            $add(
                'Sensitive files exposure',
                'fail',
                'Accessible files: ' . esc_html(implode(', ', $exposed)),
                'Remove/relocate these files or block them in the web server config.'
            );
        }
    }

    private function check_php_version($add) {
        $v = PHP_VERSION;
        $ok = version_compare($v, '8.1', '>=');
        $status = $ok ? 'pass' : 'warn';
        $add(
            'PHP version',
            $status,
            'Detected PHP ' . esc_html($v),
            $ok ? 'You’re on a supported version. Aim for 8.2+ for performance and security updates.' :
                'Upgrade PHP to 8.1 or newer (preferably 8.2+)—older versions may be EOL and lack security fixes.'
        );
    }

    private function check_php_ini($add) {
        $display_errors = (ini_get('display_errors') == 1);
        $expose_php     = (ini_get('expose_php') == 1);
        $allow_url_fopen = (ini_get('allow_url_fopen') == 1);
        $cookie_secure  = ini_get('session.cookie_secure');
        $cookie_httponly = ini_get('session.cookie_httponly');

        $issues = [];
        if ($display_errors) $issues[] = 'display_errors=On';
        if ($expose_php)     $issues[] = 'expose_php=On';
        if ($allow_url_fopen) $issues[] = 'allow_url_fopen=On';
        if (! $cookie_httponly) $issues[] = 'session.cookie_httponly=Off';
        if (is_ssl() && ! $cookie_secure) $issues[] = 'session.cookie_secure=Off (on HTTPS)';

        if (empty($issues)) {
            $add(
                'PHP ini hardening',
                'pass',
                'No common php.ini risks detected.',
                'Keep <code>display_errors</code> Off in production; prefer secure cookie flags and avoid <code>expose_php</code>.'
            );
        } else {
            $add(
                'PHP ini hardening',
                'warn',
                'Potentially risky settings: ' . esc_html(implode(', ', $issues)),
                'Set <code>display_errors=Off</code>, <code>expose_php=Off</code>, enable <code>session.cookie_httponly=1</code> and (on HTTPS) <code>session.cookie_secure=1</code>.'
            );
        }
    }

    private function check_db_version_and_modes($add) {
        global $wpdb;
        $dbv = $wpdb->db_version(); // MySQL or MariaDB
        $sql_mode = $wpdb->get_var("SELECT @@sql_mode");

        $ok_version = true;
        if ($dbv) {
            // Very rough: MySQL 8.0+ or MariaDB 10.4+ modern baseline
            $ok_version = (stripos($dbv, 'mariadb') !== false)
                ? version_compare(preg_replace('/[^0-9.].*/', '', $dbv), '10.4', '>=')
                : version_compare(preg_replace('/[^0-9.].*/', '', $dbv), '5.7', '>='); // WordPress baseline
        }

        $has_strict = (is_string($sql_mode) && (false !== stripos($sql_mode, 'STRICT_TRANS_TABLES') || false !== stripos($sql_mode, 'STRICT_ALL_TABLES')));

        $status = ($ok_version && $has_strict) ? 'pass' : ($ok_version ? 'warn' : 'fail');
        $details = 'DB: ' . esc_html($dbv ?: 'unknown') . '. SQL_MODE: ' . esc_html($sql_mode ?: 'empty');
        $rec = 'Use at least MySQL 5.7+/MariaDB 10.4+ and enable STRICT SQL modes.';
        if (! $has_strict) $rec .= ' Ask your host to add STRICT_TRANS_TABLES to sql_mode.';

        $add('Database version & SQL modes', $status, $details, $rec);
    }

    private function check_table_prefix($add) {
        global $table_prefix;
        if ($table_prefix === 'wp_') {
            $add(
                'Table prefix',
                'warn',
                'Default <code>wp_</code> prefix in use.',
                'Change to a non-default prefix on new installs to reduce automated attack noise (not a strong security boundary).'
            );
        } else {
            $add(
                'Table prefix',
                'pass',
                'Non-default prefix detected.',
                'Keep using a non-default prefix.'
            );
        }
    }

    private function check_auth_salts($add) {
        $keys = ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'];
        $bad  = [];
        foreach ($keys as $k) {
            if (! defined($k)) {
                $bad[] = $k . ' (undefined)';
                continue;
            }
            $val = constant($k);
            if (! is_string($val) || strlen($val) < 32 || stripos($val, 'put your unique phrase here') !== false) {
                $bad[] = $k;
            }
        }
        if (empty($bad)) {
            $add('Auth keys & salts', 'pass', 'All keys/salts look random & present.', 'Rotate periodically if you suspect compromise.');
        } else {
            $add(
                'Auth keys & salts',
                'fail',
                'Weak/missing: ' . esc_html(implode(', ', $bad)),
                'Regenerate keys/salts in wp-config.php using the official generator. This invalidates existing sessions.'
            );
        }
    }

    private function check_wp_debug_and_editor($add) {
        $debug = defined('WP_DEBUG') && WP_DEBUG;
        $editor = (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT) ? 'disabled' : 'enabled';

        if (! $debug && $editor === 'disabled') {
            $add(
                'WP_DEBUG & file editor',
                'pass',
                'WP_DEBUG off; theme/plugin file editor disabled.',
                'Keep WP_DEBUG off in production and file editor disabled to reduce risk.'
            );
        } else {
            $msg = [];
            if ($debug) $msg[] = 'WP_DEBUG=On';
            if ($editor === 'enabled') $msg[] = 'File editor enabled';
            $add(
                'WP_DEBUG & file editor',
                'warn',
                'Settings: ' . esc_html(implode(', ', $msg) ?: 'none'),
                'Set <code>WP_DEBUG</code> to false in production. Add <code>define("DISALLOW_FILE_EDIT", true);</code> to wp-config.php.'
            );
        }
    }

    private function check_updates($add) {
        // Core/plugins/themes update counts
        if (! function_exists('wp_get_update_data')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }
        $data = function_exists('wp_get_update_data') ? wp_get_update_data() : ['counts' => ['plugins' => 0, 'themes' => 0, 'wordpress' => 0]];
        $c = $data['counts'];

        $total = (int)$c['plugins'] + (int)$c['themes'] + (int)$c['wordpress'];
        if ($total === 0) {
            $add(
                'Updates available',
                'pass',
                'No pending core/plugin/theme updates.',
                'Keep automatic updates enabled where appropriate.'
            );
        } else {
            $details = sprintf('Core: %d, Plugins: %d, Themes: %d', (int)$c['wordpress'], (int)$c['plugins'], (int)$c['themes']);
            $add(
                'Updates available',
                'warn',
                esc_html($details),
                'Update core, plugins, and themes promptly. Outdated components are a major attack vector.'
            );
        }
    }

    private function check_xmlrpc($add) {
        $enabled = apply_filters('xmlrpc_enabled', true);
        if ($enabled) {
            $add(
                'XML-RPC availability',
                'warn',
                'XML-RPC appears enabled.',
                'If you do not use Jetpack/mobile apps/legacy integrations, disable XML-RPC (security plugin or server rule).'
            );
        } else {
            $add(
                'XML-RPC availability',
                'pass',
                'XML-RPC disabled.',
                'No action needed unless you rely on features that need XML-RPC.'
            );
        }
    }

    private function check_admin_user_and_author_enum($add) {
        // admin username
        $admin_user = get_user_by('login', 'admin');
        $has_admin  = $admin_user instanceof WP_User;

        // author enumeration via ?author=1
        $resp = $this->http_head_or_get(add_query_arg('author', 1, home_url('/')));
        $enum = ($resp['is_redirect'] && ! empty($resp['location']) && false !== strpos($resp['location'], '/author/'));

        if (! $has_admin && ! $enum) {
            $add(
                'User exposure',
                'pass',
                'No default "admin" user and author enumeration redirect not observed.',
                'Keep non-guessable usernames; if needed, block author enumeration via server rules or a security plugin.'
            );
        } else {
            $d = [];
            if ($has_admin) $d[] = 'User "admin" exists';
            if ($enum) $d[] = 'Author enumeration redirect detected';
            $add(
                'User exposure',
                'warn',
                esc_html(implode('; ', $d)),
                'Rename the "admin" account to a non-obvious username and/or restrict author archives. Use 2FA for admins.'
            );
        }
    }

    private function check_file_permissions($add) {
        $items = [
            ABSPATH . 'wp-config.php' => 0644,
            WP_CONTENT_DIR             => 0755,
            WP_PLUGIN_DIR              => 0755,
        ];
        $bad = [];
        foreach ($items as $path => $maxPerm) {
            if (file_exists($path)) {
                $p = @fileperms($path);
                if ($p !== false) {
                    $perms = $p & 0777;
                    if ($perms > $maxPerm) {
                        $bad[] = basename($path) . ' (' . decoct($perms) . ' > ' . decoct($maxPerm) . ')';
                    }
                }
            }
        }
        if (empty($bad)) {
            $add(
                'File permissions (basic)',
                'info',
                'No obvious over-permissive bits detected on common paths (heuristic only).',
                'Aim for files 0644 and directories 0755. Hosting environments vary; follow your host’s guidance.'
            );
        } else {
            $add(
                'File permissions (basic)',
                'warn',
                'Over-permissive: ' . esc_html(implode(', ', $bad)),
                'Tighten permissions—files <= 0644, directories <= 0755—per your host’s best practices.'
            );
        }
    }

    /* ========== HTTP helpers ========== */

    private function http_head_or_get($url) {
        $r = wp_remote_head(esc_url_raw($url), ['redirection' => 5, 'timeout' => 10, 'sslverify' => true]);
        if (is_wp_error($r) || (int) wp_remote_retrieve_response_code($r) === 405) {
            $r = wp_remote_get(esc_url_raw($url), ['redirection' => 5, 'timeout' => 10, 'sslverify' => true]);
        }
        return $this->normalize_http_response($r);
    }

    private function http_get($url) {
        $r = wp_remote_get(esc_url_raw($url), ['redirection' => 5, 'timeout' => 10, 'sslverify' => true]);
        return $this->normalize_http_response($r);
    }

    private function normalize_http_response($r) {
        if (is_wp_error($r)) {
            return [
                'ok'         => false,
                'status'     => 0,
                'headers'    => [],
                'body'       => '',
                'is_redirect' => false,
                'location'   => '',
                'error'      => $r->get_error_message(),
            ];
        }
        $code    = (int) wp_remote_retrieve_response_code($r);
        $headers = wp_remote_retrieve_headers($r);
        $body    = wp_remote_retrieve_body($r);

        // normalize header keys to lowercase
        $h = [];
        foreach ((array) $headers as $k => $v) {
            $h[strtolower($k)] = is_array($v) ? implode(', ', $v) : $v;
        }

        $location = $h['location'] ?? '';
        $is_redirect = in_array($code, [301, 302, 303, 307, 308], true);

        return [
            'ok'         => $code >= 200 && $code < 300,
            'status'     => $code,
            'headers'    => $h,
            'body'       => $body,
            'is_redirect' => $is_redirect,
            'location'   => $location,
            'error'      => '',
        ];
    }
}
