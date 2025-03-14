<?php

/**
 * The admin-specific functionality of the plugin.
 *
 * Defines the plugin name, version, and two examples hooks for how to
 * enqueue the admin-specific stylesheet and JavaScript.
 *
 * @package    Descope_Wp
 * @subpackage Descope_Wp/admin
 * @author     Descope
 */

class Descope_Wp_Admin
{

    /**
     * The ID of this plugin.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $plugin_name    The ID of this plugin.
     */
    private $plugin_name;

    /**
     * The version of this plugin.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $version    The current version of this plugin.
     */
    private $version;

    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.0
     * @param      string    $plugin_name       The name of this plugin.
     * @param      string    $version    The version of this plugin.
     */
    public function __construct($plugin_name, $version)
    {

        $this->plugin_name = $plugin_name;
        $this->version = $version;
    }

    /**
     * Register the stylesheets for the admin area.
     *
     * @since    1.0.0
     */
    public function enqueue_styles()
    {

        /**
         * This function is provided for demonstration purposes only.
         *
         * An instance of this class should be passed to the run() function
         * defined in Descope_Wp_Loader as all of the hooks are defined
         * in that particular class.
         *
         * The Descope_Wp_Loader will then create the relationship
         * between the defined hooks and the functions defined in this
         * class.
         */

        wp_enqueue_style($this->plugin_name, plugin_dir_url(__FILE__) . 'css/descope-wp-admin.css', array(), $this->version, 'all');
    }

    /**
     * Register the JavaScript for the admin area.
     *
     * @since    1.0.0
     */
    public function enqueue_scripts()
    {

        wp_enqueue_script($this->plugin_name, plugin_dir_url(__FILE__) . 'js/descope-wp-admin.js', array('jquery'), $this->version, false);
        wp_localize_script($this->plugin_name, 'descope_admin_ajax_object', array('ajax_url' => admin_url('admin-ajax.php'), 'security' => wp_create_nonce('sync_user_nonce')));
    }

    public function create_descope_log_directory()
    {
        $custom_log_dir = WP_CONTENT_DIR . '/descope-logs';

        if (!file_exists($custom_log_dir)) {
            wp_mkdir_p($custom_log_dir);
        }
    }

    public function descope_log($message)
    {
        if (defined('DESCOPE_LOG_FILE')) {
            $timestamp = date('Y-m-d H:i:s'); // Current date and time
            $log_message = "[$timestamp] $message";
            error_log($log_message . PHP_EOL, 3, DESCOPE_LOG_FILE);
        }
    }
    /**
     * Settings page
     *
     * @since    1.0.0
     */
    public function descope_settings_page()
    {
        add_menu_page(
            __('Descope Settings', 'descope-wp'),
            __('Descope Settings', 'descope-wp'),
            'manage_options',
            'descope-settings',
            array($this, 'descope_settings_render_settings')
        );
    }

    /**
     * Import notice
     *
     * @since    1.0.0
     */
    public function descope_import_notice()
    {
        if (get_transient('descope_import_success')) {
?>
            <div class="notice notice-success is-dismissible">
                <p><?php _e('User successfully imported to Descope.', 'descope-wp'); ?></p>
            </div>
        <?php
            delete_transient('descope_import_success');
        }

        if (get_transient('descope_import_error')) {
        ?>
            <div class="notice notice-error is-dismissible">
                <p><?php echo get_transient('descope_import_error'); ?></p>
            </div>
<?php
            delete_transient('descope_import_error');
        }
    }

    /**
     * Settings render
     *
     * @since    1.0.0
     */
    public function descope_settings_render_settings()
    {
        require_once plugin_dir_path(__FILE__) . 'partials/descope-settings.php';
    }

    /**
     * API call
     *
     * @since    1.0.0
     */
    public function make_curl_post_request($url, $authorization_token, $data = null)
    {
        $headers = [
            'Authorization' => 'Bearer ' . trim($authorization_token),
            'Content-Type' => 'application/json'
        ];

        $body = $data ? json_encode($data) : '';

        $response = wp_remote_post($url, [
            'headers' => $headers,
            'body' => $body
        ]);

        if (is_wp_error($response)) {
            return [
                'response' => '',
                'httpcode' => '',
                'error' => $response->get_error_message()
            ];
        } else {
            return [
                'response' => wp_remote_retrieve_body($response),
                'httpcode' => wp_remote_retrieve_response_code($response),
                'error' => ''
            ];
        }
    }

    /**
     * Import user
     *
     * @since    1.0.0
     */
    public function import_wp_user_to_descope($user)
    {
        // Fetch phone from user meta
        $phone = get_user_meta($user->ID, 'phone', true);
        $phone = empty($phone) ? null : $phone;

        // Fetch dynamic fields configuration
        $customAttributes = get_option('dynamic_fields');
        $userMeta = array();

        if ($customAttributes) {
            // Map dynamic fields as descope_field => wp_field
            foreach ($customAttributes as $attribute) {
                $descope_field = $attribute['descope_field'];
                $wp_field = $attribute['wp_field'];
                $userMeta[$descope_field] = get_user_meta($user->ID, $wp_field, true);
            }
        }

        $user_data = [
            "loginId" => $user->user_login,
            "email" => $user->user_email,
            "givenName" => $user->first_name,
            "familyName" => $user->last_name,
            "phone" => $user->user_phone,
            "displayName" => $user->display_name,
            "roleNames" => $user->roles,
            "status" => 'enabled',
            "customAttributes" => empty($userMeta) ? null : $userMeta
        ];

        $descope_api_url_create = 'https://api.descope.com/v1/mgmt/user/create';
        $descope_api_url_search = 'https://api.descope.com/v1/mgmt/user/search';
        $descope_api_url_update = 'https://api.descope.com/v1/mgmt/user/update';

        $project_id = get_option('client_id'); // Project ID
        $management_key = get_option('management_key'); // Management Key

        // Concatenate project ID and management key to form authorization token
        $authorization_token = $project_id . ':' . $management_key;

        // Search for user by loginId
        $search_data = ["loginId" => $user_data['loginId']];
        $search_result = $this->make_curl_post_request($descope_api_url_search, $authorization_token, $search_data);

        if ($search_result['httpcode'] == 200) {
            $search_response = json_decode($search_result['response'], true);

            if (!empty($search_response) && !empty($search_response['users'])) {
                // User exists, try to update user
                $this->descope_log("Descope API Request: URL - $descope_api_url_update, Method - POST, Data - " . json_encode($user_data));
                $update_result = $this->make_curl_post_request($descope_api_url_update, $authorization_token, $user_data);

                if ($update_result['httpcode'] == 200 || $update_result['httpcode'] == 201) {
                    set_transient('descope_import_success', true, 30);
                    return true; // Successfully updated user
                } else {
                    // Handle error and possibly fallback to create if the error indicates user does not exist
                    if ($update_result['httpcode'] == 500 && strpos($update_result['response'], 'Could not update user') !== false) {
                        $this->descope_log('Descope API error (update): HTTP ' . $update_result['httpcode'] . ' - ' . $update_result['response'] . ' - cURL Error: ' . $update_result['error']);

                        // User does not exist, so create user instead
                        $this->descope_log("Descope API Request: URL - $descope_api_url_create, Method - POST, Data - " . json_encode($user_data));
                        $create_result = $this->make_curl_post_request($descope_api_url_create, $authorization_token, $user_data);

                        if ($create_result['httpcode'] == 200 || $create_result['httpcode'] == 201) {
                            set_transient('descope_import_success', true, 30);
                            return true; // Successfully created user
                        } else {
                            $this->descope_log('Descope API error (create): HTTP ' . $create_result['httpcode'] . ' - ' . $create_result['response'] . ' - cURL Error: ' . $create_result['error']);
                            set_transient('descope_import_error', 'Descope API error (create): HTTP ' . $create_result['httpcode'] . ' - ' . $create_result['response'], 30);
                            return false; // Failed to create user
                        }
                    } else {
                        $this->descope_log('Descope API error (update): HTTP ' . $update_result['httpcode'] . ' - ' . $update_result['response'] . ' - cURL Error: ' . $update_result['error']);
                        set_transient('descope_import_error', 'Descope API error (update): HTTP ' . $update_result['httpcode'] . ' - ' . $update_result['response'], 30);
                        return false; // Failed to update user
                    }
                }
            } else {
                // User does not exist, create user
                $this->descope_log("Descope API Request: URL - $descope_api_url_create, Method - POST, Data - " . json_encode($user_data));
                $create_result = $this->make_curl_post_request($descope_api_url_create, $authorization_token, $user_data);

                if ($create_result['httpcode'] == 200 || $create_result['httpcode'] == 201) {
                    set_transient('descope_import_success', true, 30);
                    return true; // Successfully created user
                } else {
                    $this->descope_log('Descope API error (create): HTTP ' . $create_result['httpcode'] . ' - ' . $create_result['response'] . ' - cURL Error: ' . $create_result['error']);
                    set_transient('descope_import_error', 'Descope API error (create): HTTP ' . $create_result['httpcode'] . ' - ' . $create_result['response'], 30);
                    return false; // Failed to create user
                }
            }
        } else {
            $this->descope_log('Descope API error (search): HTTP ' . $search_result['httpcode'] . ' - ' . $search_result['response'] . ' - cURL Error: ' . $search_result['error']);
            set_transient('descope_import_error', 'Descope API error (search): HTTP ' . $search_result['httpcode'] . ' - ' . $search_result['response'], 30);
            return false; // Failed to search user
        }
    }

    /**
     * Sync all user
     *
     * @since    1.0.0
     */
    public function sync_all_subscribers_to_descope($role)
    {
        $args = [
            'role'     => !empty($role) ? $role : 'subscriber',
            'orderby'  => 'user_nicename',
            'order'    => 'ASC'
        ];
        $users = get_users($args);

        foreach ($users as $user) {
            $result = $this->import_wp_user_to_descope($user);
            if (!$result) {
                // Handle the error accordingly
                error_log('Failed to import user: ' . $user->user_email);
            }
        }
    }
    /**
     * Add a descope interval for every minute
     *
     * @since    1.0.0
     */
    public function add_descope_cron_schedules($schedules)
    {
        $schedules['every_day'] = array(
            'interval' => 86400, // Seconds set 
            'display'  => esc_html__('Every 24 Hours'),
        );
        return $schedules;
    }

    public function debug_log_page()
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $log_file = WP_CONTENT_DIR . '/descope-logs/descope.log';

        echo '<div class="wrap">';
        echo '<h3>' . __('Sync Users Log', 'descope-wp') . '</h3>';
        echo '<div id="log-content">';
        if (file_exists($log_file)) {
            $log_content = file_get_contents($log_file);
            if (!empty($log_content)) {
                echo '<pre style="background: #fff; padding: 10px; border: 1px solid #ccc; max-height: 600px; overflow: auto;">';
                echo esc_html($log_content);
                echo '</pre>';
            } else {
                echo '<p>' . __('No log found.', 'descope-wp') . '</p>';
            }
        } else {
            echo '<p>' . __('No log found.', 'descope-wp') . '</p>';
        }
        echo '</div>';
        echo '</div>';
    }

    public function sync_users_to_descope_callback()
    {
        check_ajax_referer('sync_user_nonce', 'security');

        $selected_role = isset($_POST['user_role']) ? sanitize_text_field($_POST['user_role']) : '';

        // Get all users with the selected role
        $args = [
            'role' => !empty($selected_role) ? $selected_role : 'subscriber',
            'orderby' => 'user_nicename',
            'order' => 'ASC'
        ];
        $users = get_users($args);

        $total_users = count($users);
        $synced_users = 0;

        foreach ($users as $user) {
            $result = $this->import_wp_user_to_descope($user);
            if ($result) {
                $synced_users++;
            }

            // Calculate progress
            $progress = ($synced_users / $total_users) * 100;

            // Output progress
            echo json_encode([
                'progress' => $progress,
                'message' => "Synced $synced_users of $total_users users."
            ]);

            // Flush the output buffer to send the update
            ob_flush();
            flush();
        }

        wp_die();
    }

    public function clear_log_file_callback()
    {
        check_ajax_referer('sync_user_nonce', 'security');

        $log_file = WP_CONTENT_DIR . '/descope-logs/descope.log';

        if (file_exists($log_file)) {
            file_put_contents($log_file, '');
            wp_send_json_success(['message' => __('Log cleared successfully.', 'descope-wp')]);
        } else {
            wp_send_json_error(['message' => __('Log file not found.', 'descope-wp')]);
        }
    }
}
