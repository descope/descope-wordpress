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
 * Plugin Name:       Descope Wordpress Auth Plugin
 * Description:       Add password-less authentication and user management to your site with Descope OIDC.
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
define('DESCOPE_LOG_FILE', WP_CONTENT_DIR . '/descope-logs/descope.log');
define('DESCOPE_METADATA_FILE', plugin_dir_path( __DIR__ ) . 'descope-wp/metadata.xml');

/**
 * The code that runs during plugin activation.
 * This action is documented in includes/class-descope-wp-activator.php
 */
function activate_descope_wp()
{
    require_once plugin_dir_path(__FILE__) . 'includes/class-descope-wp-activator.php';
    Descope_Wp_Activator::activate();
}

/**
 * The code that runs during plugin deactivation.
 * This action is documented in includes/class-descope-wp-deactivator.php
 */
function deactivate_descope_wp()
{
    require_once plugin_dir_path(__FILE__) . 'includes/class-descope-wp-deactivator.php';
    Descope_Wp_Deactivator::deactivate();
}

register_activation_hook(__FILE__, 'activate_descope_wp');
register_deactivation_hook(__FILE__, 'deactivate_descope_wp');

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
function run_descope_wp()
{

    $plugin = new Descope_Wp();
    $plugin->run();
}
run_descope_wp();