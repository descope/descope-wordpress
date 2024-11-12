<?php

/**
 * Fired during plugin activation
 *
 * @link       https://xyz.com
 * @since      1.0.0
 *
 * @package    Descope_Wp
 * @subpackage Descope_Wp/includes
 */

/**
 * Fired during plugin activation.
 *
 * This class defines all code necessary to run during the plugin's activation.
 *
 * @since      1.0.0
 * @package    Descope_Wp
 * @subpackage Descope_Wp/includes
 * @author     Dipak <dmakvana33@gmail.com>
 */
class Descope_Wp_Activator
{

    /**
     * Short Description. (use period)
     *
     * Long Description.
     *
     * @since    1.0.0
     */
    public static function activate()
    {
        if (!wp_next_scheduled('sync_subscribers_to_descope_cron_job')) {
            wp_schedule_event(time(), 'every_day', 'sync_subscribers_to_descope_cron_job');
        }
    }
}
