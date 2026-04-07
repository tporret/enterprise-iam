<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

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
				'trust_path'       => wp_json_encode( array() ),
				'aaguid'           => $source->aaguid->toRfc4122(),
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
			new EmptyTrustPath(),
			$aaguid,
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			base64_decode( $row['public_key'] ),
			(string) $row['user_id'],
			(int) $row['sign_count'],
		);
	}
}
