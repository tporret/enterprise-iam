<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages the custom credentials table for WebAuthn passkeys.
 */
final class DatabaseManager {

	private const SCHEMA_VERSION = 3;
	private const SCHEMA_VERSION_OPTION = 'enterprise_auth_credentials_schema_version';

	/**
	 * Return the full table name including the WP prefix.
	 */
	public static function table_name(): string {
		global $wpdb;
		return $wpdb->prefix . 'enterprise_auth_credentials';
	}

	/**
	 * Create or update the credentials table using dbDelta().
	 * Hooked to plugin activation.
	 */
	public static function activate(): void {
		global $wpdb;

		$table   = self::table_name();
		$charset = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NOT NULL,
			credential_id varchar(255) NOT NULL,
			public_key longtext NOT NULL,
			sign_count bigint(20) unsigned NOT NULL DEFAULT 0,
			transports text NOT NULL,
			attestation_type varchar(64) NOT NULL DEFAULT 'none',
			trust_path text NOT NULL,
			aaguid varchar(64) NOT NULL DEFAULT '',
			backup_eligible tinyint(1) DEFAULT NULL,
			backup_status tinyint(1) DEFAULT NULL,
			uv_initialized tinyint(1) DEFAULT NULL,
			compliance_status varchar(32) NOT NULL DEFAULT 'compliant',
			registration_origin varchar(255) NOT NULL DEFAULT '',
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at datetime DEFAULT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY credential_id (credential_id),
			KEY user_id (user_id)
		) {$charset};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		$origin = PasskeyPolicy::current_registration_origin();
		// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET compliance_status = %s WHERE compliance_status = '' OR compliance_status IS NULL", PasskeyPolicy::COMPLIANCE_STATUS_COMPLIANT ) );
		$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET registration_origin = %s WHERE registration_origin = '' OR registration_origin IS NULL", $origin ) );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		update_option( self::SCHEMA_VERSION_OPTION, self::SCHEMA_VERSION, false );
	}

	/**
	 * Upgrade the credentials table when the plugin schema changes.
	 */
	public static function maybe_upgrade(): void {
		$installed_version = (int) get_option( self::SCHEMA_VERSION_OPTION, 0 );

		if ( $installed_version >= self::SCHEMA_VERSION ) {
			return;
		}

		self::activate();
	}
}
