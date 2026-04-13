<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\TrustPath\TrustPath;

/**
 * Repository that stores / loads PublicKeyCredentialSource objects
 * from the custom wp_enterprise_auth_credentials table.
 */
final class CredentialRepository {

	public const COMPLIANCE_STATUS_COMPLIANT = 'compliant';
	public const COMPLIANCE_STATUS_LEGACY_NON_COMPLIANT = 'legacy_non_compliant';

	/**
	 * Find a single credential by its binary credential ID.
	 */
	public static function find_by_credential_id( string $credential_id_binary ): ?PublicKeyCredentialSource {
		global $wpdb;

		// WebAuthn stores credential IDs as binary; DB stores base64 text.
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		$b64   = base64_encode( $credential_id_binary );
		$table = DatabaseManager::table_name();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$row = $wpdb->get_row(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT * FROM {$table} WHERE credential_id = %s LIMIT 1", $b64 ),
			ARRAY_A
		);

		if ( ! $row ) {
			return null;
		}

		return self::row_to_source( $row );
	}

	/**
	 * Retrieve all credential sources for a given WP user ID.
	 *
	 * @return PublicKeyCredentialSource[]
	 */
	public static function find_all_for_user( int $user_id ): array {
		global $wpdb;

		$table = DatabaseManager::table_name();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT * FROM {$table} WHERE user_id = %d", $user_id ),
			ARRAY_A
		);

		if ( ! $rows ) {
			return array();
		}

		return array_map( array( self::class, 'row_to_source' ), $rows );
	}

	/**
	 * Persist a new credential after successful registration.
	 */
	public static function save( PublicKeyCredentialSource $source, int $user_id, string $compliance_status = self::COMPLIANCE_STATUS_COMPLIANT, string $registration_origin = '' ): void {
		global $wpdb;

		$table = DatabaseManager::table_name();
		$trust_path = self::serialize_trust_path( $source->trustPath );

		// Accessing third-party object properties keeps their upstream names.
		// phpcs:disable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		$wpdb->insert(
			$table,
			array(
				'user_id'          => $user_id,
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				'credential_id'    => base64_encode( $source->publicKeyCredentialId ),
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				'public_key'       => base64_encode( $source->credentialPublicKey ),
				'sign_count'       => $source->counter,
				'transports'       => wp_json_encode( $source->transports ),
				'attestation_type' => $source->attestationType,
				'trust_path'       => $trust_path,
				'aaguid'           => $source->aaguid->toRfc4122(),
				'backup_eligible'  => self::bool_to_db_value( $source->backupEligible ),
				'backup_status'    => self::bool_to_db_value( $source->backupStatus ),
				'uv_initialized'   => self::bool_to_db_value( $source->uvInitialized ),
				'compliance_status' => $compliance_status,
				'registration_origin' => $registration_origin,
				'created_at'       => current_time( 'mysql', true ),
				'last_used_at'     => null,
			)
		);
		// phpcs:enable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
	}

	/**
	 * Update the sign count after a successful assertion (clone detection).
	 */
	public static function update_counter( string $credential_id_binary, int $new_count ): void {
		global $wpdb;

		$table = DatabaseManager::table_name();

		$wpdb->update(
			$table,
			array( 'sign_count' => $new_count ),
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			array( 'credential_id' => base64_encode( $credential_id_binary ) ),
			array( '%d' ),
			array( '%s' )
		);
	}

	/**
	 * Update sign count and last-used time after a successful assertion.
	 */
	public static function record_successful_assertion( string $credential_id_binary, int $new_count ): void {
		global $wpdb;

		$table = DatabaseManager::table_name();

		$wpdb->update(
			$table,
			array(
				'sign_count'   => $new_count,
				'last_used_at' => current_time( 'mysql', true ),
			),
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			array( 'credential_id' => base64_encode( $credential_id_binary ) ),
			array( '%d', '%s' ),
			array( '%s' )
		);
	}

	/**
	 * Retrieve the stored compliance and audit metadata for a credential.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function find_metadata_by_credential_id( string $credential_id_binary ): ?array {
		$row = self::find_row_by_credential_id( $credential_id_binary );

		if ( ! $row ) {
			return null;
		}

		return array(
			'user_id' => (int) $row['user_id'],
			'compliance_status' => (string) ( $row['compliance_status'] ?? self::COMPLIANCE_STATUS_COMPLIANT ),
			'backup_eligible' => self::db_value_to_bool( $row['backup_eligible'] ?? null ),
			'backup_status' => self::db_value_to_bool( $row['backup_status'] ?? null ),
			'registration_origin' => (string) ( $row['registration_origin'] ?? '' ),
			'created_at' => (string) ( $row['created_at'] ?? '' ),
			'last_used_at' => (string) ( $row['last_used_at'] ?? '' ),
		);
	}

	public static function mark_backup_eligible_credentials_legacy_non_compliant(): void {
		global $wpdb;

		$table = DatabaseManager::table_name();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table} SET compliance_status = %s WHERE backup_eligible = 1",
				self::COMPLIANCE_STATUS_LEGACY_NON_COMPLIANT
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	public static function restore_legacy_non_compliant_credentials(): void {
		global $wpdb;

		$table = DatabaseManager::table_name();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table} SET compliance_status = %s WHERE compliance_status = %s",
				self::COMPLIANCE_STATUS_COMPLIANT,
				self::COMPLIANCE_STATUS_LEGACY_NON_COMPLIANT
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	public static function user_has_compliant_credential( int $user_id ): bool {
		return self::user_has_credential_with_status( $user_id, self::COMPLIANCE_STATUS_COMPLIANT );
	}

	public static function user_has_legacy_non_compliant_credential( int $user_id ): bool {
		return self::user_has_credential_with_status( $user_id, self::COMPLIANCE_STATUS_LEGACY_NON_COMPLIANT );
	}

	public static function delete_legacy_non_compliant_for_user( int $user_id ): void {
		global $wpdb;

		$table = DatabaseManager::table_name();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE user_id = %d AND compliance_status = %s",
				$user_id,
				self::COMPLIANCE_STATUS_LEGACY_NON_COMPLIANT
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/**
	 * Convert a DB row to a PublicKeyCredentialSource.
	 */
	private static function row_to_source( array $row ): PublicKeyCredentialSource {
		$transports = json_decode( $row['transports'] ?? '[]', true );
		if ( ! is_array( $transports ) ) {
			$transports = array();
		}

		$aaguid = $row['aaguid']
			? Uuid::fromString( $row['aaguid'] )
			: Uuid::fromString( '00000000-0000-0000-0000-000000000000' );

		return PublicKeyCredentialSource::create(
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			base64_decode( $row['credential_id'] ),
			'public-key',
			$transports,
			$row['attestation_type'] ?? 'none',
			self::deserialize_trust_path( $row['trust_path'] ?? null ),
			$aaguid,
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			base64_decode( $row['public_key'] ),
			hash( 'sha256', (string) $row['user_id'], true ),
			(int) $row['sign_count'],
			null,
			self::db_value_to_bool( $row['backup_eligible'] ?? null ),
			self::db_value_to_bool( $row['backup_status'] ?? null ),
			self::db_value_to_bool( $row['uv_initialized'] ?? null ),
		);
	}

	/**
	 * @return array<string, mixed>|null
	 */
	private static function find_row_by_credential_id( string $credential_id_binary ): ?array {
		global $wpdb;

		$table = DatabaseManager::table_name();
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		$b64   = base64_encode( $credential_id_binary );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$row = $wpdb->get_row(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT * FROM {$table} WHERE credential_id = %s LIMIT 1", $b64 ),
			ARRAY_A
		);

		return $row ?: null;
	}

	private static function user_has_credential_with_status( int $user_id, string $status ): bool {
		global $wpdb;

		$table = DatabaseManager::table_name();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$count = (int) $wpdb->get_var(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT COUNT(1) FROM {$table} WHERE user_id = %d AND compliance_status = %s", $user_id, $status )
		);

		return $count > 0;
	}

	private static function serialize_trust_path( TrustPath $trust_path ): string {
		try {
			$normalized = WebAuthnHelper::serializer()->normalize( $trust_path );
		} catch ( \Throwable ) {
			$normalized = array();
		}

		$json = wp_json_encode( $normalized );

		return false === $json ? '[]' : $json;
	}

	private static function deserialize_trust_path( ?string $trust_path_json ): TrustPath {
		if ( empty( $trust_path_json ) ) {
			return EmptyTrustPath::create();
		}

		$trust_path = json_decode( $trust_path_json, true );
		if ( ! is_array( $trust_path ) ) {
			return EmptyTrustPath::create();
		}

		try {
			$deserialized = WebAuthnHelper::serializer()->denormalize( $trust_path, TrustPath::class );
			if ( $deserialized instanceof TrustPath ) {
				return $deserialized;
			}
		} catch ( \Throwable ) {
			return EmptyTrustPath::create();
		}

		return EmptyTrustPath::create();
	}

	private static function bool_to_db_value( ?bool $value ): ?int {
		if ( null === $value ) {
			return null;
		}

		return $value ? 1 : 0;
	}

	private static function db_value_to_bool( mixed $value ): ?bool {
		if ( null === $value || '' === $value ) {
			return null;
		}

		return 1 === (int) $value;
	}
}
