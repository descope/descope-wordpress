<?php
/**
 * Admin AJAX for WordPress.
 *
 * @package WordPress
 * @subpackage Administration
 */

define( 'DOING_AJAX', true );
define( 'WP_ADMIN', true );
define( 'WP_BLOG_ID', 1 );
define( 'ABSPATH', dirname( __FILE__ ) . '/../' );

// Load WordPress Bootstrap
require_once( ABSPATH . 'wp-load.php' );

// Include the necessary files
require_once( ABSPATH . 'wp-admin/includes/admin.php' );

// Verify nonce and permission
if ( ! isset( $_POST['action'] ) ) {
    die();
}

$action = sanitize_key( $_POST['action'] );
do_action( 'wp_ajax_' . $action );

if ( isset( $_POST['wpnonce'] ) && ! wp_verify_nonce( $_POST['wpnonce'], $action ) ) {
    wp_die( 'Security check failed.' );
}

// Allow ajax callbacks to call hooks
do_action( 'wp_ajax_' . $action );