<?php
/**
 * Plugin Name: Enterprise Auth – Identity & Access Management
 * Plugin URI:  https://porretto.com/enterprise-auth
 * Description: Enterprise-grade Identity & Access Management for WordPress. Zero Trust security hardening, REST API lockdown, and a modern React admin UI.
 * Version:     1.5.0
 * Requires PHP: 8.1
 * Author:      tporret
 * License:     GPL-2.0-or-later
 * Donate link: https://porretto.com/donate
 * Text Domain: enterprise-auth
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// ── Constants ───────────────────────────────────────────────────────────────
define( 'ENTERPRISE_AUTH_VERSION', '1.4.0' );
define( 'ENTERPRISE_AUTH_FILE', __FILE__ );
define( 'ENTERPRISE_AUTH_DIR', plugin_dir_path( __FILE__ ) );
define( 'ENTERPRISE_AUTH_URL', plugin_dir_url( __FILE__ ) );

// ── PHP version gate ────────────────────────────────────────────────────────
if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
	add_action(
		'admin_notices',
		static function (): void {
			echo '<div class="notice notice-error"><p>';
			echo esc_html__( 'Enterprise Auth requires PHP 8.1 or higher.', 'enterprise-auth' );
			echo '</p></div>';
		}
	);
	return;
}

// ── Autoloader ──────────────────────────────────────────────────────────────
$autoloader = ENTERPRISE_AUTH_DIR . 'vendor/autoload.php';
if ( ! file_exists( $autoloader ) ) {
	add_action(
		'admin_notices',
		static function (): void {
			echo '<div class="notice notice-error"><p>';
			echo esc_html__( 'Enterprise Auth: Composer autoloader not found. Please run <code>composer install</code>.', 'enterprise-auth' );
			echo '</p></div>';
		}
	);
	return;
}
require_once $autoloader;

// ── Activation ──────────────────────────────────────────────────────────────
register_activation_hook( __FILE__, array( \EnterpriseAuth\Plugin\DatabaseManager::class, 'activate' ) );

// ── Boot ────────────────────────────────────────────────────────────────────
( new \EnterpriseAuth\Plugin\Core() )->init();
