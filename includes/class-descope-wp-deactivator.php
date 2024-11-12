<?php

/**
 * Fired during plugin deactivation.
 *
 * This class defines all code necessary to run during the plugin's deactivation.
 *
 * @since      1.0.0
 * @package    Descope_Wp
 * @subpackage Descope_Wp/includes
 * @author     Descope
 */
class Descope_Wp_Deactivator
{

    public static function deactivate()
    {
        $timestamp = wp_next_scheduled('sync_subscribers_to_descope_cron_job');
        wp_unschedule_event($timestamp, 'sync_subscribers_to_descope_cron_job');
    }
}
