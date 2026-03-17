<?php

use Jumbojett\OpenIDConnectClient;

class Descope_Wp_Public
{
    private $plugin_name;
    private $version;
    private $oidc;
    private $baseUrl;
    private $client_id;
    private $client_secret;
    private $redirect_uri;
    private $token_endpoint;
    private $userinfo_endpoint;
    private $descope_metadata;
    private $spBaseUrl;
    private $settingsInfo;
    private $auth;
    private $flowId;
    private $providerId;
    private $dynamic_fields;
    private $redirectPagePath;
    private $return_to;
    
    public function __construct($plugin_name, $version)
    {
        $this->plugin_name = $plugin_name;
        $this->version = $version;

        $this->client_id = get_option('descope_client_id');
        $this->baseUrl = get_option('descope_base_url');
        $this->client_secret = get_option('descope_client_secret');
        $this->redirect_uri = site_url('/wp-login.php?action=oidc_callback');
        $this->token_endpoint = get_option('descope_token_endpoint');
        $this->userinfo_endpoint = get_option('descope_userinfo_endpoint');
        $this->descope_metadata = get_option('descope_metadata');
        $this->dynamic_fields = get_option('descope_dynamic_fields');
        $spBaseUrl = site_url();

        if($this->descope_metadata){
            $this->settingsInfo = array (
                'strict' => true,
                'debug' => false,
                'sp' => array (
                    'entityId' => site_url(),
                    'assertionConsumerService' => array (
                        'url' => $spBaseUrl.'/?acs',
                        'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
                    ),
                    'singleLogoutService' => array (
                        'url' => $spBaseUrl.'/?sls',
                        'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                    ),
                    'NameIDFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                ),
                'idp' => array (
                    'entityId' => get_option('descope_entity_id'),
                    'singleSignOnService' => array (
                        'url' => get_option('descope_sso_url'),
                        'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                    ),
                    'singleLogoutService' => array (
                        'url' => get_option('descope_sso_url'),
                        'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                    ),
                    'x509cert' => str_replace(' ', '', get_option('descope_x_certificate')),
                ),
            );

            try {
                $this->auth = new OneLogin_Saml2_Auth($this->settingsInfo);
            } catch (Exception $e) {
                error_log('SAML initialization error: ' . $e->getMessage());
                error_log('SAML settings: ' . print_r($this->settingsInfo, true));
            }
        }

        // Initialize session and OIDC client on WordPress init
        add_action('init', array($this, 'descope_start_session'), 1);
        add_action('init', array($this, 'descope_init_oidc'));
        add_action('login_form_oidc_login', array($this, 'descope_oidc_login'));

        //kept old shortcodes for backward compatibility
        add_shortcode('descope_oidc_login_form', array($this, 'descope_login_form'));
        add_shortcode('oidc_login_form', array($this, 'descope_login_form'));

        add_shortcode('descope_wc', array($this, 'descope_web_component'));

        add_shortcode('descope_saml_login_form', array($this, 'descope_saml_login_form'));
        add_shortcode('saml_login_form', array($this, 'descope_saml_login_form'));

        add_shortcode('descope_logout_button', array($this, 'descope_logout_button'));
        add_shortcode('logout_button', array($this, 'descope_logout_button'));

        add_shortcode('descope_user_profile_widget', array($this, 'descope_user_profile_widget'));
        add_shortcode('user_profile_widget', array($this, 'descope_user_profile_widget'));
        
        add_action('login_form_oidc_callback', array($this, 'descope_oidc_callback'));
        add_action('init', array($this, 'descope_init_sso'));

        add_action('init', array($this, 'register_shortcodes'));
        add_action('wp_logout', array($this, 'descope_end_session'));
    }

    public function enqueue_styles()
    {
        wp_enqueue_style($this->plugin_name, plugin_dir_url(__FILE__) . 'css/descope-wp-public.css', array(), $this->version, 'all');
    }

    public function enqueue_scripts()
    {
        wp_enqueue_script('descope-web-component', 'https://descopecdn.com/npm/@descope/web-component@3.21.0/dist/index.js', array('jquery'), $this->version, false);
        wp_enqueue_script('descope-web-js', 'https://descopecdn.com/npm/@descope/web-js-sdk@1.16.0/dist/index.umd.js', array('jquery'), $this->version, false);
        wp_enqueue_script('jwt-decode', 'https://unpkg.com/jwt-decode@3.1.2/build/jwt-decode.js', array('jquery'), $this->version, false);
        wp_enqueue_script('descope-user-profile-widget', 'https://static.descope.com/npm/@descope/user-profile-widget@0.0.93/dist/index.js', array('jquery'), $this->version, false);
        wp_enqueue_script($this->plugin_name, plugin_dir_url(__FILE__) . 'js/descope-wp-public.js', array('jquery'), $this->version, false);

        wp_localize_script($this->plugin_name, 'descope_ajax_object', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('custom_nonce'),
            'siteUrl' => get_site_url(),
            'clientId' => get_option('descope_client_id'),
            'baseUrl' => get_option('descope_base_url'),
            'flowId' => $this->flowId,
            'dynamicFields' => get_option('descope_dynamic_fields'),
            'logoutUrl' => wp_logout_url(home_url()),
            'providerId' => $this->providerId,
            'redirectPagePath' => $this->redirectPagePath
        ));
    }

    // Register Shortcodes
    public function register_shortcodes() {
        //kept old shortcodes for backward compatibility
        add_shortcode('descope_onetap_form', array($this, 'descope_onetap'));
        add_shortcode('onetap_form', array($this, 'descope_onetap'));

        add_shortcode('descope_protected_page', array($this, 'descope_protected_page'));
        add_shortcode('protected_page', array($this, 'descope_protected_page'));
    }

    // Start PHP session if not already started
    public function descope_start_session()
    {
        if (!session_id()) {
            session_start();
        }
    }

    // Destroy PHP session on logout
    public function descope_end_session()
    {
        session_destroy();

        //backup in case jquery on click event does not attach properly
        if (isset($_COOKIE['DSR'])) {
            unset($_COOKIE['DSR']);            
        }  
        if (isset($_COOKIE['DS'])) {
            unset($_COOKIE['DS']);            
        }  
    }

    // Initialize OIDC client
    public function descope_init_oidc()
    { 
        if (isset($_POST['descope_client_id']) && 
            isset($_POST['descope_client_secret']) && 
            isset($_POST['descope_management_key']) && 
            isset($_POST['descope_issuer_url']) && 
            isset($_POST['descope_authorization_endpoint']) && 
            isset($_POST['descope_token_endpoint']) && 
            isset($_POST['descope_userinfo_endpoint'])) {

            // Initialize OpenID Connect client
            $this->oidc = new OpenIDConnectClient(
                get_option('descope_authorization_endpoint'),
                $this->client_id,
                $this->client_secret
            );

            // Configure additional parameters
            $this->oidc->providerConfigParam([
                'token_endpoint' => $this->token_endpoint,
                'userinfo_endpoint' => $this->userinfo_endpoint,
            ]);

            $this->oidc->setRedirectURL($this->redirect_uri);
            $this->oidc->addScope(['openid', 'profile', 'email']);
            $this->oidc->setResponseTypes(['code']);
            $this->oidc->setClientID($this->client_id);
            $this->oidc->setClientSecret($this->client_secret);
        }
    }

    // Redirect user to OIDC provider for authentication
    public function descope_oidc_login()
    {
        // Generate state with return path
        $state = base64_encode(json_encode([
            'nonce' => wp_create_nonce('oidc_state'),
            'return_to' => $this->return_to
        ]));
        
        $auth_url = get_option('descope_authorization_endpoint') . '?' . http_build_query([
            'client_id' => $this->client_id,
            'redirect_uri' => site_url('/wp-login.php?action=oidc_callback'),
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'state' => $state,
        ]);

        if (!headers_sent()) {
            wp_redirect($auth_url);
            exit;
        } else {
            // Fallback to JavaScript if headers were sent
            ?>
            <script>window.location.href = <?php echo json_encode(esc_url_raw($auth_url)); ?>;</script>
            <?php
            exit;
        }
    }

    // Callback function to handle OIDC provider response
    public function descope_oidc_callback()
    {
        if (!session_id()) {
            session_start();
        }
        try {
                            // Verify state parameter to prevent CSRF
                if (!isset($_GET['state']) || empty($_GET['state'])) {
                    throw new Exception('State parameter missing from callback');
                }

                // Decode the state parameter
                $state_data = json_decode(base64_decode($_GET['state']), true);
                if (!$state_data) {
                    throw new Exception('Invalid state format');
                }

                // Verify the nonce
                if (!wp_verify_nonce($state_data['nonce'], 'oidc_state')) {
                    throw new Exception('Invalid state nonce');
                }

                // Get the return URL from state
                $return_path = isset($state_data['return_to']) ? $state_data['return_to'] : '';
                $return_url = home_url($return_path);

            // Exchange authorization code for tokens
            $tokens = $this->exchangeAuthorizationCodeForTokens($_GET['code']);

            // Fetch user info using access token
            $access_token = $tokens['access_token'];
            $user_info = $this->requestUserInfoWithCurl($access_token);

            // Retrieve or create the WordPress user
            $user_email = $user_info['email'];
            $user = get_user_by('email', $user_email);

            if (!$user) {
                // Create new user if not exists
                $user_id = wp_create_user($user_email, wp_generate_password(), $user_email);
                $user = get_user_by('id', $user_id);
            }

            // Set up WordPress user
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID);

            // Use the stored return URL from earlier in the callback
            if (!headers_sent()) {
               wp_redirect($return_url?:home_url());
               exit;
            } else {
                // Fallback to JavaScript if headers were sent
                ?>
                <script>window.location.href = <?php echo json_encode(esc_url_raw($return_url?:home_url())); ?>;</script>
                <?php
                exit;
            }
        } catch (Exception $e) {
            // Handle errors gracefully
            error_log('OIDC callback error: ' . $e->getMessage());
            wp_die('Login failed: ' . $e->getMessage());
        }
    }

    public function descope_protected_page($atts) {
        // Parse attributes with defaults
        $atts = shortcode_atts(array(
            'redirect_page_path' => '',
            'return_to' => ''
        ), $atts);
        
        $this->redirectPagePath = $atts['redirect_page_path'];
        
        if (!is_user_logged_in()) {
            if ($this->redirectPagePath === '/oidc_login') {
                // Pass return path to OIDC login
                $this->return_to = $atts['return_to'];     
                do_action('login_form_oidc_login');
                exit;
            } else {
                if (!headers_sent()) {
                  wp_redirect(home_url().$this->redirectPagePath);
                   exit;
                } else {
                    // Fallback to JavaScript if headers were sent
                    ?>
                    <script>window.location.href = <?php echo json_encode(esc_url_raw(home_url().$this->redirectPagePath)); ?>;</script>
                    <?php
                    exit;
                }
            }
        }
    }

    public function descope_onetap($atts) {
        global $wp;
        $this->providerId = $atts['provider_id'] ?? 'google';
        if ( !is_user_logged_in() ) {
            ob_start();
            if (isset($_GET['sso'])) {
                $this->auth->login();
                $_SESSION['AuthNRequestID'] = $this->auth->getLastRequestID();
            }
            ?>
                <div id="descope-onetap-container" style="outline: none;"></div>
            <?php
            $output_string = ob_get_contents();
            ob_end_clean();
            return $output_string;
       }
    }

    // Render OIDC login form shortcode
    public function descope_login_form() {
        ob_start();
        if (isset($_GET['sso'])) {
            $this->auth->login();
            $_SESSION['AuthNRequestID'] = $this->auth->getLastRequestID();
        }
        global $wp;
        if ( !is_user_logged_in() ) {
            ?>
            <center><a href="<?php echo esc_url(site_url('/wp-login.php?action=oidc_login')); ?>">
                <?php esc_html_e('Login', 'descope'); ?>
            </a></center>
            <?php
        }
        else {
            ?>
            <center><a class="logoutButton" title="Logout">Logout</a></center>
            <?php
        }
        $output_string = ob_get_contents();
        ob_end_clean();
        return $output_string;
    }

    private function exchangeAuthorizationCodeForTokens($authorization_code)
    {
        $response = wp_remote_post($this->token_endpoint, [
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $authorization_code,
                'redirect_uri' => $this->redirect_uri,
                'client_id' => $this->client_id,
                'client_secret' => $this->client_secret,
            ],
        ]);

        if (is_wp_error($response)) {
            throw new Exception('Error fetching tokens: ' . $response->get_error_message());
        }

        $http_code = wp_remote_retrieve_response_code($response);
        if ($http_code !== 200) {
            $response_body = wp_remote_retrieve_body($response);
            throw new Exception('Error fetching tokens: HTTP ' . $http_code . ' - ' . $response_body);
        }

        $token_data = json_decode(wp_remote_retrieve_body($response), true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Error decoding token response JSON: ' . json_last_error_msg());
        }

        return $token_data;
    }

    private function requestUserInfoWithCurl($access_token)
    {
        $response = wp_remote_get($this->userinfo_endpoint, [
            'headers' => [
                'Authorization' => 'Bearer ' . $access_token,
            ],
        ]);

        if (is_wp_error($response)) {
            throw new Exception('Error fetching user info: ' . $response->get_error_message());
        }

        $http_code = wp_remote_retrieve_response_code($response);
        if ($http_code !== 200) {
            $response_body = wp_remote_retrieve_body($response);
            throw new Exception('Error fetching user info: HTTP ' . $http_code . ' - ' . $response_body);
        }

        $user_info = json_decode(wp_remote_retrieve_body($response), true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Error decoding user info JSON: ' . json_last_error_msg());
        }

        return $user_info;
    }
    public function descope_web_component($atts)
    {
        $this->flowId = $atts['flow_id'];
        ob_start();
        if (isset($_GET['sso'])) {
            $this->auth->login();
            $_SESSION['AuthNRequestID'] = $this->auth->getLastRequestID();
        }
        ?>
            <div id="descope-flow-container" style="outline: none;"></div>
        <?php
        $output_string = ob_get_contents();
        ob_end_clean();
        return $output_string;
    }
    public function descope_user_profile_widget($atts)
    {
        ob_start();
        ?>
            <div id="descope-user-profile-container" style="outline: none;"></div>
        <?php
        $output_string = ob_get_contents();
        ob_end_clean();
        return $output_string;
    }
    public function descope_saml_login_form()
    {
        ob_start();
        if (isset($_GET['sso'])) {
            $this->auth->login();
        }
    ?>
    <!-- <div id="descope-flow-container"></div> -->    
    <?php
        global $wp;
        if ( !is_user_logged_in() ) {
            ?>
            <center><a href="?sso">Login</a></center>
            <?php
        }
        else {
            ?>
            <center><a class="logoutButton" title="Logout">Logout</a></center>
            <?php
        }
        $output_string = ob_get_contents();
        ob_end_clean();
        return $output_string;
    }

    public function descope_logout_button()
    {
        ob_start();
        global $wp;
        if ( is_user_logged_in() ) {
            ?>
            <center><a class="logoutButton" title="Logout">Logout</a></center>
            <?php
        }
        $output_string = ob_get_contents();
        ob_end_clean();
        return $output_string;
    }

    public function descope_init_sso(){
        if (isset($_GET['acs'])) {
            error_log("ACS endpoint hit.");

            if (!isset($_POST['SAMLResponse'])) {
            error_log("Error: SAMLResponse not found in POST data.");
            return;
        }
            if (isset($_SESSION) && isset($_SESSION['AuthNRequestID'])) {
                $requestID = $_SESSION['AuthNRequestID'];
            } else {
                $requestID = null;
            }

            $this->auth->processResponse($requestID);
                 $errors = $this->auth->getErrors();
        
            if (!empty($errors)) {
                echo '<p>',implode(', ', $errors),'</p>';
                if ($this->auth->getSettings()->isDebugActive()) {
                    echo '<p>' . wp_kses($this->auth->getLastErrorReason(), array('p' => array(), 'br' => array())) . '</p>';
                }
            }
        
            if (!$this->auth->isAuthenticated()) {
                echo "<p>Not authenticated</p>";
                exit();
            }
            
            
            $_SESSION['samlUserdata'] = $this->auth->getAttributes();

            $user_email = $_SESSION['samlUserdata']['email'][0];
            $user = get_user_by('email', $user_email);

            if (!$user) {
                // Create new user if not exists
                $user_id = wp_create_user($user_email, wp_generate_password(), $user_email);
                $user = get_user_by('id', $user_id);
            }

            // Log in the user and redirect
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID);
            if (!headers_sent()) {
               wp_redirect(home_url());
               exit;
            } else {
                // Fallback to JavaScript if headers were sent
                ?>
                <script>window.location.href = <?php echo json_encode(esc_url_raw(home_url())); ?>;</script>
                <?php
                exit;
            }
        }
    }

    public function create_wp_user_ajax_handler()
    {
        check_ajax_referer('custom_nonce', 'nonce');

        $session_token = sanitize_text_field($_POST['sessionToken']);

        if (empty($session_token)) {
            wp_send_json_error(array('message' => 'Missing session token.'));
        }

        // Validate session token server-side via Descope API
        $project_id = get_option('descope_client_id');
        $base_api_url = 'https://api.descope.com';
        if (strlen($project_id) >= 32) {
            $region = substr($project_id, 1, 4);
            $base_api_url = 'https://api.' . $region . '.descope.com';
        }

        $validate_response = wp_remote_post($base_api_url . '/v1/auth/validate', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $session_token,
                'Content-Type'  => 'application/json',
            ),
            'body'    => '{}',
            'timeout' => 10,
        ));

        if (is_wp_error($validate_response) || wp_remote_retrieve_response_code($validate_response) !== 200) {
            wp_send_json_error(array('message' => 'Invalid session token.'));
        }

        // Extract verified user info from Descope response
        $validated_body = json_decode(wp_remote_retrieve_body($validate_response), true);
        $token_claims = isset($validated_body['parsedJWT']) ? $validated_body['parsedJWT'] : null;

        $user_details = json_decode(stripslashes($_POST['userDetails']), true);

        if (!$user_details || !isset($user_details['email'])) {
            wp_send_json_error(array('message' => 'Invalid user details.'));
        }

        $email = sanitize_email($user_details['email']);
        $username = sanitize_user($user_details['email']);
        $password = wp_generate_password();

        // Use server-side field mappings only — never trust client-supplied dynamicFields
        $fields = get_option('descope_dynamic_fields');
        if (!is_array($fields)) {
            $fields = array();
        }

        // Block sensitive meta keys that control privileges
        $blocked_meta_keys = array(
            'wp_capabilities', 'wp_user_level', 'capabilities', 'user_level',
            'wp_user_roles', 'role', 'roles',
        );
        // Also block any prefixed variations (e.g. custom table prefix)
        $fields = array_filter($fields, function ($item) use ($blocked_meta_keys) {
            $wp_field = isset($item['wp_field']) ? strtolower($item['wp_field']) : '';
            foreach ($blocked_meta_keys as $blocked) {
                if ($wp_field === $blocked || strpos($wp_field, '_capabilities') !== false || strpos($wp_field, '_user_level') !== false) {
                    return false;
                }
            }
            return true;
        });

        // Use token claims from server-validated response for field mapping
        $decoded_token = is_array($token_claims) ? $token_claims : array();

        // Check if user exists, if not, create a new one
        if (!email_exists($email) && !username_exists($username)) {
            $user_id = wp_create_user($username, $password, $email);

            if (is_wp_error($user_id)) {
                wp_send_json_error(array('message' => 'User creation failed.'));
            }
            update_user_meta($user_id, 'session_token', $session_token);

            // Iterate through server-side field mapping and update user meta
            foreach ($fields as $item) {
                $descope_field = $item['descope_field'];
                $wp_field = $item['wp_field'];
                $custom_attribute_value = $decoded_token[$descope_field] ?? 'Not Found';
                update_user_meta($user_id, $wp_field, $custom_attribute_value);
            }

            // Auto login the user
            wp_set_current_user($user_id);
            wp_set_auth_cookie($user_id, true);
            do_action('wp_login', $username, get_userdata($user_id));
        } else {
            // If user exists, log them in
            $user = get_user_by('email', $email);

            // Iterate through server-side field mapping and update user meta
            foreach ($fields as $item) {
                $descope_field = $item['descope_field'];
                $wp_field = $item['wp_field'];
                $custom_attribute_value = $decoded_token[$descope_field] ?? 'Not Found';
                update_user_meta($user->ID, $wp_field, $custom_attribute_value);
            }

            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID, true);
            do_action('wp_login', $user->user_login, $user);
        }

        // Send the redirect URL back to the JS
        wp_send_json_success(array('redirect_url' => home_url()));
        wp_die();
    }

    public function basic_client()
    {
        $client_credentials = base64_encode($this->client_id . ':' . $this->client_secret);

        $headers = array(
            'Authorization' => 'Basic ' . $client_credentials,
            'Content-Type' => 'application/x-www-form-urlencoded'
        );

        $body = array(
            'grant_type' => 'client_credentials',
            'scope' => 'openid profile email phone descope.claims descope.custom_claims',
            'response_type' => 'code'
        );
        
        if (isset($_POST['descope_token_endpoint'])) {
            $response = wp_remote_post($this->token_endpoint, array(
                'headers' => $headers,
                'body' => $body,
                'timeout' => 30
            ));

            if (is_wp_error($response)) {
                error_log('Error: ' . $response->get_error_message());
                return;
            }

            $response_body = wp_remote_retrieve_body($response);
            $tokenResponse = json_decode($response_body);

            if (isset($tokenResponse->access_token)) {
                $_SESSION['access_token'] = $tokenResponse->access_token;
            } else {
                error_log('Error: No access token received. Response: ' . $response_body);
            }            
        }
    }
}
