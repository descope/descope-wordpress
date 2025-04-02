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

    // Generate and store state parameter for CSRF protection
    private function generateState()
    {
        $state = bin2hex(random_bytes(16));
        $_SESSION['oidc_state'] = $state;
        return $state;
    }

    // Redirect user to OIDC provider for authentication
    public function descope_oidc_login()
    {
        $auth_url = get_option('descope_authorization_endpoint') . '?' . http_build_query([
            'client_id' => $this->client_id,
            'redirect_uri' => site_url('/wp-login.php?action=oidc_callback'),
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'state' => $this->generateState(),
        ]);

        wp_redirect($auth_url);
        exit;
    }

    // Callback function to handle OIDC provider response
    public function descope_oidc_callback()
    {
        try {
            // Verify state parameter to prevent CSRF
            if (!isset($_GET['state']) || empty($_GET['state'])) {
                throw new Exception('State parameter missing from callback');
            }

            $state = $_GET['state'];
            $storedState = isset($_SESSION['oidc_state']) ? $_SESSION['oidc_state'] : null;

            if ($state !== $storedState) {
                throw new Exception('Invalid state parameter');
            }

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

            // Log in the user and redirect
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID);
            wp_redirect(home_url());
            exit;
        } catch (Exception $e) {
            // Handle errors gracefully
            error_log('OIDC callback error: ' . $e->getMessage());
            wp_die('Login failed: ' . $e->getMessage());
        }
    }

    public function descope_protected_page($atts) {
        global $wp;
        $this->redirectPagePath = $atts['redirect_page_path'];
        if ( !is_user_logged_in() ) {
            wp_redirect(home_url().$this->redirectPagePath);
            exit;
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
                <?php echo esc_html_e('Login', 'descope'); ?>
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
            wp_redirect(home_url());
            exit;
        }
    }

    public function create_wp_user_ajax_handler()
    {
        check_ajax_referer('custom_nonce', 'nonce');

        $user_details = json_decode(stripslashes($_POST['userDetails']), true);
        $decoded_token = json_decode(stripslashes($_POST['decodedToken']), true);
        $session_token = sanitize_text_field($_POST['sessionToken']);
        $fields = json_decode(stripslashes($_POST['dynamicFields']), true);
        
        if (!$user_details || !$session_token) {
            wp_send_json_error(array('message' => 'Invalid user details or session token.'));
        }

        // Extract user information from $user_details
        $email = sanitize_email($user_details['email']);
        $username = sanitize_user($user_details['email']);
        $password = wp_generate_password();

        // Check if user exists, if not, create a new one
        if (!email_exists($email) && !username_exists($username)) {
            $user_id = wp_create_user($username, $password, $email);

            if (is_wp_error($user_id)) {
                wp_send_json_error(array('message' => 'User creation failed.'));
            }
            // Optionally update user meta or roles
            update_user_meta($user_id, 'session_token', $session_token);

            // iterate through custom field mapping and update user meta
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

            // iterate through custom field mapping and update user meta
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