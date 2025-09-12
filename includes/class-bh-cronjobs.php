<?php
/**
 * BlackHaven Messenger Cron Jobs
 * Handles scheduled tasks for the BlackHaven Messenger plugin.
 */

class BH_CronJobs {

    public function __construct() {
        add_action('bh_cron_hourly', array($this, 'run_hourly'));
        add_action('bh_cron_12hourly', array($this, 'run_12hourly'));
        add_action('bh_cron_daily', array($this, 'run_daily'));

        // Schedule events if not already scheduled
        if (!wp_next_scheduled('bh_cron_hourly')) {
            wp_schedule_event(time(), 'hourly', 'bh_cron_hourly');
        }
        if (!wp_next_scheduled('bh_cron_12hourly')) {
            add_filter('cron_schedules', array($this, 'add_12hour_cron_schedule'));
            wp_schedule_event(time(), '12hourly', 'bh_cron_12hourly');
        }
        if (!wp_next_scheduled('bh_cron_daily')) {
            wp_schedule_event(time(), 'daily', 'bh_cron_daily');
        }
    }

    // Add custom interval for 12 hours
    public function add_12hour_cron_schedule($schedules) {
        $schedules['12hourly'] = array(
            'interval' => 12 * 60 * 60,
            'display'  => __('Every 12 Hours')
        );
        return $schedules;
    }

    public function run_hourly() {
        // Your hourly cron job code here
    }

    public function run_12hourly() {
        // Your 12-hour cron job code here
    }

    public function run_daily() {
        // Your daily cron job code here
    }
}

// Initialize the cron jobs
new BH_CronJobs();