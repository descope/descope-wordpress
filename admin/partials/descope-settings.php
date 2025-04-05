<?php
if (!defined('ABSPATH'))
    exit; // Exit if accessed directly

$nonce_code = 'descope-settings';
$nonce = wp_create_nonce($nonce_code);

// Default values
$default_tab = null;
$entityID = get_option('descope_entity_id', null);
$ssoURL = get_option('descope_sso_url', null);
$signingCertificate = get_option('descope_x_certificate', null);
$projectID = get_option('descope_project_id', null);
$baseUrl = get_option('descope_base_url');

$tab = isset($_GET['tab']) ? $_GET['tab'] : $default_tab;

if (isset($_POST['save-config'])) {
    // Verify nonce with proper sanitization
    if (!isset($_POST['nonce']) || !wp_verify_nonce(
        sanitize_text_field(wp_unslash($_POST['nonce'])),
        $nonce_code
    )) {
        wp_die('Security check failed.');
    }

    if ($tab == 'sso-configuration') {
        if (isset($_POST['descope_metadata']) && isset($_POST['descope_sso_management_key'])) {
            // Update options using text sanitization
            update_option('descope_metadata', sanitize_text_field($_POST['descope_metadata']));
            update_option('descope_sso_management_key', sanitize_text_field($_POST['descope_sso_management_key']));

            // Process the metadata and update values
            $metadata_url = sanitize_text_field($_POST['descope_metadata']);
            $xml_metadata_content = !empty($metadata_url) ? @file_get_contents($metadata_url) : null;

            if ($xml_metadata_content) {
                $xml_metadata = simplexml_load_string($xml_metadata_content, 'SimpleXMLElement', LIBXML_NOCDATA);

                if ($xml_metadata && isset($xml_metadata->IDPSSODescriptor)) {
                    foreach ($xml_metadata->IDPSSODescriptor->SingleSignOnService as $service) {
                        $entityID = sanitize_text_field((string) $xml_metadata['entityID']);
                        $ssoURL = sanitize_text_field((string) $service['Location']);

                        if ($service['Binding'] == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect') {
                            $service['Location'] = sanitize_text_field($service['Location']);
                        } elseif ($service['Binding'] == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') {
                            $service['Location'] = sanitize_text_field($service['Location']);
                        }
                    }

                    // Parse the URL and sanitize components
                    $parsed_url = parse_url($entityID);
                    $path_parts = explode('/', trim($parsed_url['path'] ?? '', '/'));
                    $parts = explode('-', $path_parts[0]);
                    $projectID = sanitize_text_field($parts[0]);

                    $signingCertificate = sanitize_text_field((string) $xml_metadata->IDPSSODescriptor->KeyDescriptor[0]->KeyInfo->X509Data->X509Certificate);
                    $encryptionCertificate = sanitize_text_field((string) $xml_metadata->IDPSSODescriptor->KeyDescriptor[1]->KeyInfo->X509Data->X509Certificate);

                    // Update options with sanitized text
                    update_option('descope_entity_id', sanitize_text_field($entityID));
                    update_option('descope_sso_url', sanitize_text_field($ssoURL));
                    update_option('descope_project_id', sanitize_text_field($projectID));
                    update_option('descope_x_certificate', sanitize_text_field($signingCertificate));

                    // Save certificates
                    $x_signingCertificate = str_replace(' ', '', sanitize_text_field($signingCertificate));
                    $x_encryptionCertificate = str_replace(' ', '', sanitize_text_field($encryptionCertificate));

                    update_option('descope_x_certificate', sanitize_text_field($x_signingCertificate));

                    // XML file handling
                    if (file_exists(DESCOPE_METADATA_FILE)) {
                        $xml = simplexml_load_file(DESCOPE_METADATA_FILE);
                    } else {
                        // Create new XML with sanitized values
                        $xml = new SimpleXMLElement('<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"></EntityDescriptor>');
                        $xml->addAttribute('entityID', sanitize_text_field($entityID));
                        
                        $idpDesc = $xml->addChild('IDPSSODescriptor');
                        $idpDesc->addAttribute('protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol');
                        
                        for ($i = 0; $i < 2; $i++) {
                            $keyDesc = $idpDesc->addChild('KeyDescriptor');
                            $keyDesc->addAttribute('use', $i == 0 ? 'signing' : 'encryption');
                            $keyInfo = $keyDesc->addChild('KeyInfo');
                            $keyInfo->addAttribute('xmlns', 'http://www.w3.org/2000/09/xmldsig#');
                            $x509Data = $keyInfo->addChild('X509Data');
                            $x509Data->addChild('X509Certificate', '');
                        }
                        
                        $ssoService = $idpDesc->addChild('SingleSignOnService');
                        $ssoService->addAttribute('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
                        $ssoService->addAttribute('Location', sanitize_text_field($ssoURL));
                    }

                    if ($xml) {
                        $xml['entityID'] = sanitize_text_field($entityID);
                        
                        if (isset($xml->IDPSSODescriptor->KeyDescriptor[0]->KeyInfo->X509Data->X509Certificate)) {
                            $xml->IDPSSODescriptor->KeyDescriptor[0]->KeyInfo->X509Data->X509Certificate = sanitize_text_field($x_signingCertificate);
                        }
                        if (isset($xml->IDPSSODescriptor->KeyDescriptor[1]->KeyInfo->X509Data->X509Certificate)) {
                            $xml->IDPSSODescriptor->KeyDescriptor[1]->KeyInfo->X509Data->X509Certificate = sanitize_text_field($x_encryptionCertificate);
                        }
                        
                        $xml->asXML(DESCOPE_METADATA_FILE);
                    }
                }
            } else {
                error_log('Unable to load Descope metadata XML.');
            }
        }

        // OIDC Configuration
        if (isset($_POST['descope_client_id'])) {
            update_option('descope_client_id', sanitize_text_field($_POST['descope_client_id']));
        }
        if (isset($_POST['descope_client_secret'])) {
            update_option('descope_client_secret', sanitize_text_field($_POST['descope_client_secret']));
        }
        if (isset($_POST['descope_management_key'])) {
            update_option('descope_management_key', sanitize_text_field($_POST['descope_management_key']));
        }
        if (isset($_POST['descope_issuer_url'])) {
            update_option('descope_issuer_url', sanitize_text_field($_POST['descope_issuer_url']));
        }
        if (isset($_POST['descope_authorization_endpoint'])) {
            update_option('descope_authorization_endpoint', sanitize_text_field($_POST['descope_authorization_endpoint']));
        }
        if (isset($_POST['descope_token_endpoint'])) {
            update_option('descope_token_endpoint', sanitize_text_field($_POST['descope_token_endpoint']));
        }
        if (isset($_POST['descope_userinfo_endpoint'])) {
            update_option('descope_userinfo_endpoint', sanitize_text_field($_POST['descope_userinfo_endpoint']));
        }
    } else if ($tab == 'sync-users') {
        $new = array();
        $descope_field = !empty($_POST['descope_field']) ? $_POST['descope_field'] : null;
        $wp_field = !empty($_POST['wp_field']) ? $_POST['wp_field'] : null;

        $count = count($descope_field);
        for ($i = 0; $i < $count; $i++) {
            if ($descope_field[$i] != ''):
                $new[$i]['descope_field'] = stripslashes(strip_tags($descope_field[$i]));
                $new[$i]['wp_field'] = stripslashes($wp_field[$i]);
            endif;
        }
        update_option('descope_dynamic_fields', $new);
    } else {
        if (isset($_POST['descope_client_id'])) {
            update_option('descope_client_id', sanitize_text_field($_POST['descope_client_id']));
        }
        if (isset($_POST['descope_base_url'])) {
            update_option('descope_base_url', sanitize_text_field($_POST['descope_base_url']));
        }
        if (isset($_POST['descope_user_sync_management_key'])) {
            update_option('descope_user_sync_management_key', sanitize_text_field($_POST['descope_user_sync_management_key']));
        }
    }
}

$dynamic_fields = get_option('descope_dynamic_fields');
?>
<div class="wrap descope-wp">
    <h1><?php echo esc_html__('Descope Configuration', 'descope'); ?></h1>
    <h2 class="nav-tab-wrapper">
        <a href="?page=descope-settings"
            class="nav-tab <?php echo esc_attr($tab === null ? 'nav-tab-active' : ''); ?>"><?php echo esc_html__('Descope Configuration', 'descope'); ?></a>
        <a href="?page=descope-settings&tab=sso-configuration"
            class="nav-tab <?php echo esc_attr($tab === 'sso-configuration' ? 'nav-tab-active' : ''); ?>"><?php echo esc_html__('SSO Configuration', 'descope'); ?></a>
        <a href="?page=descope-settings&tab=sync-users"
            class="nav-tab <?php echo esc_attr($tab === 'sync-users' ? 'nav-tab-active' : ''); ?>">
            <?php echo esc_html__('Sync Users', 'descope'); ?>
        </a>
    </h2>
</div>
<div class="tab-content">
    <form action="#" method="POST" enctype="multipart/form-data">
        <table class="form-table">
            <tbody>
                <?php
                switch ($tab):
                    case 'sso-configuration':
                        ?>
                        <tr>
                            <!-- SAML Column -->
                            <td style="width: 50%; vertical-align: top;">
                                <h2><?php echo esc_html__('SAML Configuration', 'descope'); ?></h2>
                                <table class="form-table">
                                    <!-- SAML Configuration Fields -->
                                    <tr>
                                        <th>
                                            <label><?php echo esc_html__('Metadata(XML)', 'descope'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="descope_metadata" class="regular-text"
                                                value="<?php echo esc_attr(get_option('descope_metadata')); ?>" />
                                        </td>
                                    </tr>
                                    <input type="hidden" name="descope_entity_id" class="regular-text"
                                        value="<?php echo esc_attr(isset($entityID) ? $entityID : get_option('descope_entity_id')); ?>" />
                                    <input type="hidden" name="descope_sso_url" class="regular-text"
                                        value="<?php echo esc_attr(isset($ssoURL) ? $ssoURL : get_option('descope_sso_url')); ?>" />
                                    <input type="hidden" name="descope_x_certificate" class="regular-text"
                                        value="<?php echo esc_attr(isset($signingCertificate) ? $signingCertificate : get_option('descope_x_certificate')); ?>" />
                                    <input type="hidden" name="descope_project_id" class="regular-text"
                                        value="<?php echo esc_attr(isset($projectID) ? $projectID : get_option('descope_project_id')); ?>" />
                                    <tr>
                                        <th>
                                            <label><?php echo esc_html__('Management Key', 'descope'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="descope_sso_management_key" class="regular-text"
                                                value="<?php echo esc_attr(get_option('descope_sso_management_key')); ?>" />
                                        </td>
                                    </tr>

                                </table>
                            </td>

                            <!-- OIDC Column -->
                            <td style="width: 50%; vertical-align: top;">
                                <h2><?php echo esc_html__('OIDC Configuration', 'descope'); ?></h2>
                                <table class="form-table">
                                    <!-- OIDC Configuration Fields -->
                                    <tr>
                                        <th>
                                            <label><?php echo esc_html__('Client ID', 'descope'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="descope_client_id" class="regular-text" 
                                                value="<?php echo esc_attr(get_option('descope_client_id')); ?>" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>
                                            <label><?php echo esc_html__('Client Secret', 'descope'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="descope_client_secret" class="regular-text"
                                                value="<?php echo esc_attr(get_option('descope_client_secret')); ?>" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>
                                            <label><?php echo esc_html__('Management Key', 'descope'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="descope_management_key" class="regular-text"
                                                value="<?php echo esc_attr(get_option('descope_management_key')); ?>" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>
                                            <label><?php echo esc_html__('Issuer URL', 'descope'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="descope_issuer_url" class="regular-text"
                                                value="<?php echo esc_attr(get_option('descope_issuer_url')); ?>" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>
                                            <label><?php echo esc_html__('Authorization Endpoint', 'descope'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="descope_authorization_endpoint" class="regular-text"
                                                value="<?php echo esc_attr(get_option('descope_authorization_endpoint')); ?>" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>
                                            <label><?php echo esc_html__('Token Endpoint', 'descope'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="descope_token_endpoint" class="regular-text"
                                                value="<?php echo esc_attr(get_option('descope_token_endpoint')); ?>" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>
                                            <label><?php echo esc_html__('User Info Endpoint', 'descope'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="descope_userinfo_endpoint" class="regular-text"
                                                value="<?php echo esc_attr(get_option('descope_userinfo_endpoint')); ?>" />
                                        </td>
                                    </tr>
                                </table>
                            </td>

                        </tr>
                        <?php
                        break;
                    case 'sync-users':
                        ?>
                        <tr class="dynamic">
                            <th>
                                <label><?php echo esc_html__('Custom Fields Mapping', 'descope'); ?></label>
                            </th>
                            <td>
                                <table class="form-table dynamic-table-content repeater-text-fields-table">
                                    <thead>
                                        <tr class="dynamic-heading">
                                            <th><?php echo esc_html__('Descope Fields', 'descope'); ?></th>
                                            <th><?php echo esc_html__('WordPress Fields', 'descope'); ?></th>
                                            <th><?php echo esc_html__('Action', 'descope'); ?></th>
                                        </tr>
                                    </thead>
                                    <tbody class="repeater-text-fields-wrapper">
                                        <?php
                                        if ($dynamic_fields) {
                                            foreach ($dynamic_fields as $value) {
                                                echo '<tr><td><input type="text" id="descope_field" name="descope_field[]" value="' . esc_attr($value['descope_field']) . '"></td><td><input type="text" id="wp_field" name="wp_field[]" value="' . esc_attr($value['wp_field']) . '"></td><td><button class="remove-repeater-text-field button-secondary">Remove</button></td></tr>';
                                            }
                                        } else {
                                            echo '<tr><td><input type="text" id="descope_field" name="descope_field[]" value=""></td><td><input type="text" id="wp_field" name="wp_field[]" value=""></td><td><button class="remove-repeater-text-field button-secondary">Remove</button></td></tr>';
                                        }
                                        ?>
                                    </tbody>
                                </table>
                                <a class="add-repeater-text-field button-primary"><?php echo esc_html__('Add New', 'descope'); ?></a>
                            </td>
                        </tr>
                        <?php
                        break;
                    default:
                        ?>
                        <tr>
                            <th>
                                <label><?php echo esc_html__('Project ID', 'descope'); ?></label>
                            </th>
                            <td>
                                <input type="text" name="descope_client_id" class="regular-text" 
                                    value="<?php echo esc_attr(get_option('descope_client_id')); ?>" />
                            </td>
                        </tr>
                        <tr>
                            <th>
                                <label><?php echo esc_html__('Base URL', 'descope'); ?></label>
                            </th>
                            <td>
                                <input type="text" name="descope_base_url" class="regular-text"
                                    value="<?php echo esc_attr(get_option('descope_base_url')); ?>" />
                                <p class="description"><?php echo esc_html__('Optional. Leave empty unless you have set up a custom base URL in your Descope project.', 'descope'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th>
                                <label><?php echo esc_html__('Management Key', 'descope'); ?></label>
                            </th>
                            <td>
                                <input type="text" name="descope_user_sync_management_key" class="regular-text"
                                    value="<?php echo esc_attr(get_option('descope_user_sync_management_key')); ?>" />
                                <p class="description"><?php echo esc_html__('Used for syncing users to Descope.', 'descope'); ?></p>
                            </td>
                        </tr>
                        <?php
                        break;
                endswitch;
                ?>
            </tbody>
        </table>

        <p class="submit">
            <input type="hidden" name="nonce" value="<?php echo esc_attr($nonce); ?>" />
            <input type="submit" name="save-config" class="button button-primary btn" class="regular-text"
                value="<?php echo esc_attr__('Save Configuration', 'descope'); ?>" />
        </p>
    </form>

    <?php
    if ($tab == 'sync-users') {
        ?>
        <h2><?php echo esc_html__('Sync Users', 'descope'); ?></h2>
        <hr>
        <form name="sync-user" id="sync-form" action="#" method="POST">
            <select name="user-role" id="user-role">
                <?php
                // Get all editable roles
                $editable_roles = get_editable_roles();

                // Loop through roles and add them to the dropdown
                foreach (array_reverse($editable_roles) as $role_key => $role_info) {
                    // Exclude the administrator role
                    if ($role_key !== 'administrator') {
                        echo '<option value="' . esc_attr($role_key) . '">' . esc_html($role_info['name']) . '</option>';
                    }
                }
                ?>
            </select>
            <button type="submit" name="sync-user" id="sync-user"
                class="button button-primary"><?php echo esc_html__('Sync Users', 'descope'); ?></button>
            <button id="clear-log-button" class="button button-secondary"><?php echo esc_html__('Clear Log', 'descope'); ?></button>
        </form>
        <div id="progress-container" style="display: none;">
            <div class="progress">
                <div id="progress-bar" class="progress-bar" role="progressbar" style="width: 0%;" aria-valuenow="0"
                    aria-valuemin="0" aria-valuemax="100">0%</div>
            </div>
        </div>
        <?php
        $this->debug_log_page();
    } ?>
</div>
