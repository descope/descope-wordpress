<?php

/**
 * Fired during plugin activation.
 *
 * This class defines all code necessary to run during the plugin's activation.
 *
 * @since      1.0.0
 * @package    Descope_Wp
 * @subpackage Descope_Wp/includes
 * @author     Descope
 */

class Descope_Wp_Activator
{
    public static function activate()
    {
        // Set initial version if not exists
        if (!get_option('descope_db_version')) {
            add_option('descope_db_version', '1.0.0');
        }
        
        self::migrate_options();
        if (!wp_next_scheduled('descope_sync_subscribers_to_descope_cron_job')) {
            wp_schedule_event(time(), 'every_day', 'descope_sync_subscribers_to_descope_cron_job');
        }
    }

    public static function migrate_options() {
        // Get current version
        $current_version = get_option('descope_db_version', '1.0.0');
        
        // Only run migration if version is less than 1.1.1
        if (version_compare($current_version, '1.1.1', '<')) {
            $options_to_migrate = array(
                'entity_id' => 'descope_entity_id',
                'sso_url' => 'descope_sso_url',
                'x_certificate' => 'descope_x_certificate',
                'project_id' => 'descope_project_id',
                'client_id' => 'descope_client_id',
                'base_url' => 'descope_base_url',
                'client_secret' => 'descope_client_secret',
                'token_endpoint' => 'descope_token_endpoint',
                'userinfo_endpoint' => 'descope_userinfo_endpoint',
                'metadata' => 'descope_metadata',
                'dynamic_fields' => 'descope_dynamic_fields',
                'management_key' => 'descope_management_key',
                'user_sync_management_key' => 'descope_user_sync_management_key',
                'sso_management_key' => 'descope_sso_management_key',
                'issuer_url' => 'descope_issuer_url',
                'authorization_endpoint' => 'descope_authorization_endpoint',
                'authorization_url' => 'descope_authorization_url',
                'token_url' => 'descope_token_url',
                'userinfo_url' => 'descope_userinfo_url'
            );

            foreach ($options_to_migrate as $old_key => $new_key) {
                $value = get_option($old_key);
                if ($value !== false) {
                    // Add the new option
                    add_option($new_key, $value);
                    // Delete the old option
                    delete_option($old_key);
                    error_log("Migrated $old_key to $new_key");
                }
            }

            // Update version after successful migration
            update_option('descope_db_version', '1.1.0');
        }
    }
}
