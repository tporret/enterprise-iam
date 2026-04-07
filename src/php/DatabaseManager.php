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
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			UNIQUE KEY credential_id (credential_id),
			KEY user_id (user_id)
		) {$charset};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}
}
