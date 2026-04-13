<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class NetworkIdpManager {

	private const OPTION_KEY = 'enterprise_auth_network_idps';

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function all(): array {
		$all = self::all_raw();

		foreach ( $all as &$idp ) {
			if ( isset( $idp['client_secret'] ) ) {
				$idp['client_secret'] = Encryption::decrypt( $idp['client_secret'] );
			}
		}
		unset( $idp );

		return $all;
	}

	public static function has_any(): bool {
		return count( self::all_raw() ) > 0;
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public static function find( string $id ): ?array {
		foreach ( self::all() as $idp ) {
			if ( ( $idp['id'] ?? '' ) === $id ) {
				return $idp;
			}
		}

		return null;
	}

	/**
	 * @param array<string, mixed> $idp
	 * @return true|\WP_Error
	 */
	public static function save( array $idp ) {
		try {
			if ( isset( $idp['client_secret'] ) && '' !== $idp['client_secret'] ) {
				$idp['client_secret'] = Encryption::encrypt( $idp['client_secret'] );
			}
		} catch ( \RuntimeException $e ) {
			$idp_id = sanitize_text_field( (string) ( $idp['id'] ?? '' ) );
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log(
				sprintf(
					'CRITICAL: Enterprise IAM failed to encrypt network client_secret for IdP "%s": %s',
					$idp_id,
					$e->getMessage()
				)
			);

			return new \WP_Error(
				'enterprise_auth_secret_storage_failed',
				'Failed to save IdP configuration securely. Please contact your administrator.',
				array( 'status' => 500 )
			);
		}

		$all   = self::all_raw();
		$found = false;

		foreach ( $all as $index => $existing ) {
			if ( ( $existing['id'] ?? '' ) === ( $idp['id'] ?? '' ) ) {
				$all[ $index ] = $idp;
				$found         = true;
				break;
			}
		}

		if ( ! $found ) {
			$all[] = $idp;
		}

		update_site_option( self::OPTION_KEY, array_values( $all ) );

		return true;
	}

	public static function delete( string $id ): bool {
		$all      = self::all_raw();
		$filtered = array_filter( $all, static fn( array $idp ) => ( $idp['id'] ?? '' ) !== $id );

		if ( count( $filtered ) === count( $all ) ) {
			return false;
		}

		update_site_option( self::OPTION_KEY, array_values( $filtered ) );
		return true;
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	private static function all_raw(): array {
		$raw = get_site_option( self::OPTION_KEY, array() );

		return is_array( $raw ) ? $raw : array();
	}
}