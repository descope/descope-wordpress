<?php
if (!defined('ABSPATH'))
    exit; // Exit if accessed directly

$nonce_code = 'descope-settings';
$nonce = wp_create_nonce($nonce_code);

// Default values
$default_tab = null;
$entityID = get_option('entity_id', null);
$ssoURL = get_option('sso_url', null);
$signingCertificate = get_option('x_certificate', null);
$projectID = get_option('project_id', null);
$baseUrl = get_option('base_url');
$userSyncManagementKey = get_option('user_sync_management_key');

$tab = isset($_GET['tab']) ? $_GET['tab'] : $default_tab;

if (isset($_POST['save-config'])) {
    // Verify nonce
    if (isset($_POST['nonce']) && wp_verify_nonce($_POST['nonce'], $nonce_code)) {

        if ($tab == 'sso-configuration') {
            if (isset($_POST['descope_metadata']) && isset($_POST['sso_management_key'])) {
                // Update options when form is submitted
                update_option('descope_metadata', esc_attr($_POST['descope_metadata']));
                update_option('sso_management_key', esc_attr($_POST['sso_management_key']));

            // Process the metadata and update values
            $xml_metadata_content = !empty($_POST['descope_metadata']) ? file_get_contents($_POST['descope_metadata']) : null;

            if ($xml_metadata_content) {
                $xml_metadata = simplexml_load_string($xml_metadata_content, 'SimpleXMLElement', LIBXML_NOCDATA);

                if ($xml_metadata && isset($xml_metadata->IDPSSODescriptor)) {
                    foreach ($xml_metadata->IDPSSODescriptor->SingleSignOnService as $service) {
                        $entityID = (string) $xml_metadata['entityID'];
                        $ssoURL = (string) $service['Location'];

                        if ($service['Binding'] == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect') {
                            $service['Location'] = esc_attr($service['Location']);
                        } elseif ($service['Binding'] == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') {
                            $service['Location'] = esc_attr($service['Location']);
                        }
                    }

                    // Parse the URL and extract the path
                    $parsed_url = parse_url($entityID, PHP_URL_PATH);
                    $path_parts = explode('/', trim($parsed_url, '/'));
                    $parts = explode('-', $path_parts[0]);
                    $projectID = $parts[0];

                    $signingCertificate = (string) $xml_metadata->IDPSSODescriptor->KeyDescriptor[0]->KeyInfo->X509Data->X509Certificate;
                    $encryptionCertificate = (string) $xml_metadata->IDPSSODescriptor->KeyDescriptor[1]->KeyInfo->X509Data->X509Certificate;

                    // Update the options with the parsed values
                    update_option('entity_id', esc_attr($entityID));
                    update_option('sso_url', esc_attr($ssoURL));
                    update_option('project_id', esc_attr($projectID));
                    update_option('x_certificate', esc_attr($signingCertificate));

                    // Save Metadata XML back
                    $xml = simplexml_load_file(DESCOPE_METADATA_FILE);
                    if ($xml) {
                        $xml['entityID'] = esc_attr($entityID);
            
                        $x_signingCertificate = str_replace(' ', '', esc_attr($signingCertificate));
                        $x_encryptionCertificate = str_replace(' ', '', esc_attr($encryptionCertificate));
            
                        update_option('x_certificate', esc_attr($x_signingCertificate));
            
                        // Update 'X509Certificate' values without spaces
                        $xml->IDPSSODescriptor->KeyDescriptor[0]->KeyInfo->X509Data->X509Certificate = $x_signingCertificate;
                        $xml->IDPSSODescriptor->KeyDescriptor[1]->KeyInfo->X509Data->X509Certificate = $x_encryptionCertificate;
            
                        // Save the changes back to the XML file
                        $xml->asXML(DESCOPE_METADATA_FILE);
                    }
                }
            } else {
                error_log('Unable to load Descope metadata XML.');
            }
        }

            // OIDC Configuration
            update_option('client_id', esc_attr($_POST['client_id']));
            update_option('client_secret', esc_attr($_POST['client_secret']));
            update_option('management_key', esc_attr($_POST['management_key']));
            update_option('issuer_url', esc_attr($_POST['issuer_url']));
            update_option('authorization_endpoint', esc_attr($_POST['authorization_endpoint']));
            update_option('token_endpoint', esc_attr($_POST['token_endpoint']));
            update_option('userinfo_endpoint', esc_attr($_POST['userinfo_endpoint']));
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
            update_option('dynamic_fields', $new);
        } else {
            update_option('client_id', esc_attr($_POST['client_id']));
            update_option('base_url', esc_attr($_POST['base_url']));
            update_option('user_sync_management_key', esc_attr($_POST['user_sync_management_key']));
        }
    }
}

$dynamic_fields = get_option('dynamic_fields');
?>
<div class="wrap descope-wp">
    <h1><?php _e('Descope Configuration', 'descope-wp'); ?></h1>
    <h2 class="nav-tab-wrapper">
        <a href="?page=descope-settings"
            class="nav-tab <?php if ($tab === null): ?>nav-tab-active<?php endif; ?>"><?php _e('Descope Configuration', 'descope-wp'); ?></a>
        <a href="?page=descope-settings&tab=sso-configuration"
            class="nav-tab <?php if ($tab === 'sso-configuration'): ?>nav-tab-active<?php endif; ?>"><?php _e('SSO Configuration', 'descope-wp'); ?></a>
        <a href="?page=descope-settings&tab=sync-users"
            class="nav-tab <?php if ($tab === 'sync-users'): ?>nav-tab-active<?php endif; ?>"><?php _e('Sync Users', 'descope-wp'); ?></a>
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
                                <h2><?php _e('SAML Configuration', 'descope-wp'); ?></h2>
                                <table class="form-table">
                                    <!-- SAML Configuration Fields -->
                                    <tr>
                                        <th>
                                            <label><?php _e('Metadata(XML)', 'descope-wp'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="descope_metadata" class="regular-text"
                                                value="<?php echo get_option('descope_metadata'); ?>" />
                                        </td>
                                    </tr>
                                    <input type="hidden" name="entity_id" class="regular-text"
                                        value="<?php echo isset($entityID) ? $entityID : get_option('entity_id'); ?>" />
                                    <input type="hidden" name="sso_url" class="regular-text"
                                        value="<?php echo isset($ssoURL) ? $ssoURL : get_option('sso_url'); ?>" />
                                    <input type="hidden" name="x_certificate" class="regular-text"
                                        value="<?php echo isset($signingCertificate) ? $signingCertificate : get_option('x_certificate'); ?>" />
                                    <input type="hidden" name="project_id" class="regular-text"
                                        value="<?php echo isset($projectID) ? $projectID : get_option('project_id'); ?>" />
                                    <tr>
                                        <th>
                                            <label><?php _e('Management Key', 'descope-wp'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="sso_management_key" class="regular-text"
                                                value="<?php echo get_option('sso_management_key'); ?>" />
                                        </td>
                                    </tr>

                                </table>
                            </td>

                            <!-- OIDC Column -->
                            <td style="width: 50%; vertical-align: top;">
                                <h2><?php _e('OIDC Configuration', 'descope-wp'); ?></h2>
                                <table class="form-table">
                                    <!-- OIDC Configuration Fields -->
                                    <tr>
                                        <th>
                                            <label><?php _e('Client ID', 'descope-wp'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="client_id" class="regular-text"
                                                value="<?php echo get_option('client_id'); ?>" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>
                                            <label><?php _e('Client Secret', 'descope-wp'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="client_secret" class="regular-text"
                                                value="<?php echo get_option('client_secret'); ?>" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>
                                            <label><?php _e('Management Key', 'descope-wp'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="management_key" class="regular-text"
                                                value="<?php echo get_option('management_key'); ?>" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>
                                            <label><?php _e('Issuer URL', 'descope-wp'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="issuer_url" class="regular-text"
                                                value="<?php echo get_option('issuer_url'); ?>" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>
                                            <label><?php _e('Authorization Endpoint', 'descope-wp'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="authorization_endpoint" class="regular-text"
                                                value="<?php echo get_option('authorization_endpoint'); ?>" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>
                                            <label><?php _e('Token Endpoint', 'descope-wp'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="token_endpoint" class="regular-text"
                                                value="<?php echo get_option('token_endpoint'); ?>" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>
                                            <label><?php _e('User Info Endpoint', 'descope-wp'); ?></label>
                                        </th>
                                        <td>
                                            <input type="text" name="userinfo_endpoint" class="regular-text"
                                                value="<?php echo get_option('userinfo_endpoint'); ?>" />
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
                                <label><?php _e('Custom Fields Mapping', 'descope-wp'); ?></label>
                            </th>
                            <td>
                                <table class="form-table dynamic-table-content repeater-text-fields-table">
                                    <thead>
                                        <tr class="dynamic-heading">
                                            <th><?php _e('Descope Fields', 'descope-wp'); ?></th>
                                            <th><?php _e('WordPress Fields', 'descope-wp'); ?></th>
                                            <th><?php _e('Action', 'descope-wp'); ?></th>
                                        </tr>
                                    </thead>
                                    <tbody class="repeater-text-fields-wrapper">
                                        <?php
                                        if ($dynamic_fields) {
                                            foreach ($dynamic_fields as $value) {
                                                echo '<tr><td><input type="text" id="descope_field" name="descope_field[]" value="' . $value['descope_field'] . '"></td><td><input type="text" id="wp_field" name="wp_field[]" value="' . $value['wp_field'] . '"></td><td><button class="remove-repeater-text-field button-secondary">Remove</button></td></tr>';
                                            }
                                        } else {
                                            echo '<tr><td><input type="text" id="descope_field" name="descope_field[]" value=""></td><td><input type="text" id="wp_field" name="wp_field[]" value=""></td><td><button class="remove-repeater-text-field button-secondary">Remove</button></td></tr>';
                                        }
                                        ?>
                                    </tbody>
                                </table>
                                <a class="add-repeater-text-field button-primary"><?php _e('Add New', 'descope-wp'); ?></a>
                            </td>
                        </tr>
                        <?php
                        break;
                    default:
                        ?>
                        <tr>
                            <th>
                                <label><?php _e('Project ID', 'descope-wp'); ?></label>
                            </th>
                            <td>
                                <input type="text" name="client_id" class="regular-text"
                                    value="<?php echo get_option('client_id'); ?>" />
                            </td>
                        </tr>
                        <tr>
                            <th>
                                <label><?php _e('Base URL', 'descope-wp'); ?></label>
                            </th>
                            <td>
                                <input type="text" name="base_url" class="regular-text"
                                    value="<?php echo get_option('base_url'); ?>" />
                                <p class="description"><?php _e('Optional. Leave empty unless you have set up a custom base URL in your Descope project.', 'descope-wp'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th>
                                <label><?php _e('Management Key', 'descope-wp'); ?></label>
                            </th>
                            <td>
                                <input type="text" name="user_sync_management_key" class="regular-text"
                                    value="<?php echo get_option('user_sync_management_key'); ?>" />
                                <p class="description"><?php _e('Used for syncing users to Descope.', 'descope-wp'); ?></p>
                            </td>
                        </tr>
                        <?php
                        break;
                endswitch;
                ?>
            </tbody>
        </table>

        <p class="submit">
            <input type="hidden" name="nonce" value="<?php echo $nonce; ?>" />
            <input type="submit" name="save-config" class="button button-primary btn" class="regular-text"
                value="<?php _e('Save Configuration', 'descope-wp'); ?>" />
        </p>
    </form>

    <?php
    if ($tab == 'sync-users') {
        ?>
        <h2><?php _e('Sync Users', 'descope-wp'); ?></h2>
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
                class="button button-primary"><?php _e('Sync Users', 'descope-wp'); ?></button>
            <button id="clear-log-button" class="button button-secondary"><?php _e('Clear Log', 'descope-wp'); ?></button>
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
