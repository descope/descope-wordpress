<?php

/**
 * The plugin bootstrap file
 *
 * This file is read by WordPress to generate the plugin information in the plugin
 * admin area. This file also includes all of the dependencies used by the plugin,
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin.
 *
 * @link              https://www.descope.com/
 * @since             1.0.0
 * @package           Descope_Wp
 *
 * @wordpress-plugin
 * Plugin Name:       Descope
 * Description:       Add drag and drop authentication to your site with Descope.
 * Version:           1.0.0
 * Author:            Descope
 * Author URI:        https://www.descope.com/
 * License:           GPL2
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

/**
 * Current plugin version.
 */
define('DESCOPE_WP_VERSION', '1.0.0');

// Use uploads directory for metadata.xml
function descope_get_metadata_file_path() {
    $upload_dir = wp_upload_dir();
    $plugin_upload_dir = $upload_dir['basedir'] . '/descope';
    
    // Create the directory if it doesn't exist
    if (!file_exists($plugin_upload_dir)) {
        wp_mkdir_p($plugin_upload_dir);
    }
    
    return $plugin_upload_dir . '/metadata.xml';
}
define('DESCOPE_METADATA_FILE', descope_get_metadata_file_path());

/**
 * The code that runs during plugin activation.
 * This action is documented in includes/class-descope-wp-activator.php
 */
function descope_activate_wp()
{
    require_once plugin_dir_path(__FILE__) . 'includes/class-descope-wp-activator.php';
    Descope_Wp_Activator::activate();
}

/**
 * The code that runs during plugin deactivation.
 * This action is documented in includes/class-descope-wp-deactivator.php
 */
function descope_deactivate_wp()
{
    require_once plugin_dir_path(__FILE__) . 'includes/class-descope-wp-deactivator.php';
    Descope_Wp_Deactivator::deactivate();
}

register_activation_hook(__FILE__, 'descope_activate_wp');
register_deactivation_hook(__FILE__, 'descope_deactivate_wp');

/**
 * The core plugin class that is used to define internationalization,
 * admin-specific hooks, and public-facing site hooks.
 */

require plugin_dir_path(__FILE__) . '/vendor/autoload.php';

require plugin_dir_path(__FILE__) . '/_toolkit_loader.php';

require plugin_dir_path(__FILE__) . 'includes/class-descope-wp.php';

/**
 * Begins execution of the plugin.
 *
 * Since everything within the plugin is registered via hooks,
 * then kicking off the plugin from this point in the file does
 * not affect the page life cycle.
 *
 * @since    1.0.0
 */
function descope_run_wp()
{
    $plugin = new Descope_Wp();
    
    // Check if migration is needed
    if (version_compare(get_option('descope_db_version', '1.0.0'), '1.1.0', '<')) {
        require_once plugin_dir_path(__FILE__) . 'includes/class-descope-wp-activator.php';
        Descope_Wp_Activator::migrate_options();
    }
    
    $plugin->run();
}
descope_run_wp();