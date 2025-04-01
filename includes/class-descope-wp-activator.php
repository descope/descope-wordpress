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
        if (!wp_next_scheduled('descope_sync_subscribers_to_descope_cron_job')) {
            wp_schedule_event(time(), 'every_day', 'descope_sync_subscribers_to_descope_cron_job');
        }
    }
}
