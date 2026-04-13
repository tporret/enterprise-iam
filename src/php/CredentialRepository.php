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
	public static function save( PublicKeyCredentialSource $source, int $user_id ): void {
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
				'created_at'       => current_time( 'mysql', true ),
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
