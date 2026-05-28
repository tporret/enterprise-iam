<?php
/**
 * Plugin Name: Enterprise Auth – Identity & Access Management
 * Plugin URI:  https://porretto.com/enterprise-auth
 * Description: Enterprise-grade Identity & Access Management for WordPress. Zero Trust security hardening, REST API lockdown, and a modern React admin UI.
 * Version:     1.8.1
 * Requires at least: 6.0
 * Tested up to: 7.0
 * Requires PHP: 8.3
 * Author:      tporret
 * License:     GPL-2.0-or-later
 * Donate link: https://porretto.com/donate
 * Text Domain: enterprise-auth
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// ── Constants ───────────────────────────────────────────────────────────────
define( 'ENTERPRISE_AUTH_VERSION', '1.8.1' );
define( 'ENTERPRISE_AUTH_FILE', __FILE__ );
define( 'ENTERPRISE_AUTH_DIR', plugin_dir_path( __FILE__ ) );
define( 'ENTERPRISE_AUTH_URL', plugin_dir_url( __FILE__ ) );

function enterprise_auth_missing_dependencies_notice( string $detail = '' ): void {
	if ( '' !== $detail ) {
		error_log( 'Enterprise Auth dependency load failure: ' . $detail );
	}

	add_action(
		'admin_notices',
		static function (): void {
			echo '<div class="notice notice-error"><p>';
			echo esc_html__( 'Enterprise Auth could not load its Composer dependencies. Reinstall the plugin dependencies with composer install or deploy a release package that includes vendor/.', 'enterprise-auth' );
			echo '</p></div>';
		}
	);
}

// ── PHP version gate ────────────────────────────────────────────────────────
if ( version_compare( PHP_VERSION, '8.3', '<' ) ) {
	add_action(
		'admin_notices',
		static function (): void {
			echo '<div class="notice notice-error"><p>';
			echo esc_html__( 'Enterprise Auth requires PHP 8.3 or higher.', 'enterprise-auth' );
			echo '</p></div>';
		}
	);
	return;
}

// ── Autoloader ──────────────────────────────────────────────────────────────
$autoloader = ENTERPRISE_AUTH_DIR . 'vendor/autoload.php';
if ( ! file_exists( $autoloader ) ) {
	enterprise_auth_missing_dependencies_notice( 'Composer autoloader not found at ' . $autoloader );
	return;
}

$autoload_warning = '';
set_error_handler(
	static function ( int $errno, string $errstr ) use ( &$autoload_warning ): bool {
		$autoload_warning = $errstr;
		return true;
	}
);

try {
	require_once $autoloader;
} catch ( Throwable $exception ) {
	restore_error_handler();
	enterprise_auth_missing_dependencies_notice( trim( $autoload_warning . ' ' . $exception->getMessage() ) );
	return;
}
restore_error_handler();

$database_manager_class = \EnterpriseAuth\Plugin\DatabaseManager::class;
$core_class             = \EnterpriseAuth\Plugin\Core::class;
$cli_bootstrap_class    = \EnterpriseAuth\Plugin\CLI\Bootstrap::class;
$dependency_classes     = array(
	\Webauthn\PublicKeyCredentialSource::class,
	\Jumbojett\OpenIDConnectClient::class,
	\OneLogin\Saml2\Auth::class,
	\SimpleSAML\SAML2\Constants::class,
);

try {
	$required_classes_loaded = class_exists( $database_manager_class ) && class_exists( $core_class );
} catch ( Throwable $exception ) {
	enterprise_auth_missing_dependencies_notice( $exception->getMessage() );
	return;
}

if ( ! $required_classes_loaded ) {
	enterprise_auth_missing_dependencies_notice( 'Composer autoloader did not load required plugin classes.' );
	return;
}

try {
	foreach ( $dependency_classes as $dependency_class ) {
		if ( ! class_exists( $dependency_class ) ) {
			enterprise_auth_missing_dependencies_notice( 'Composer autoloader did not load ' . $dependency_class . '.' );
			return;
		}
	}
} catch ( Throwable $exception ) {
	enterprise_auth_missing_dependencies_notice( $exception->getMessage() );
	return;
}

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	try {
		if ( class_exists( $cli_bootstrap_class ) ) {
			$cli_bootstrap_class::register();
		}
	} catch ( Throwable $exception ) {
		enterprise_auth_missing_dependencies_notice( $exception->getMessage() );
		return;
	}
}

// ── Activation ──────────────────────────────────────────────────────────────
register_activation_hook( __FILE__, array( $database_manager_class, 'activate' ) );

// ── Boot ────────────────────────────────────────────────────────────────────
$database_manager_class::maybe_upgrade();
( new $core_class() )->init();
