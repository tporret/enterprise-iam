<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages Identity Provider (IdP) configurations stored in wp_options.
 *
 * Each IdP entry contains:
 *  - id            (string, unique UUID)
 *  - provider_name (string)
 *  - protocol      ('oidc' | 'saml')
 *  - client_id / entity_id
 *  - client_secret / certificate
 *  - authorization_endpoint / sso_url
 *  - token_endpoint (OIDC only)
 *  - userinfo_endpoint (OIDC only)
 *  - domain_mapping (string[])
 *  - role_mapping   (array<string,string>)  IdP group → WP role
 *  - enabled        (bool)
 */
final class IdpManager {

	private const OPTION_KEY = 'enterprise_auth_idps';

	// ── Read ────────────────────────────────────────────────────────────────

	/**
	 * Return all IdP configurations.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function all(): array {
		$raw = get_option( self::OPTION_KEY, [] );
		return is_array( $raw ) ? $raw : [];
	}

	/**
	 * Find a single IdP by its id.
	 *
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
	 * Find the first enabled IdP whose domain_mapping contains $domain.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function find_by_domain( string $domain ): ?array {
		$domain = strtolower( trim( $domain ) );

		foreach ( self::all() as $idp ) {
			if ( empty( $idp['enabled'] ) ) {
				continue;
			}
			$domains = array_map( 'strtolower', (array) ( $idp['domain_mapping'] ?? [] ) );
			if ( in_array( $domain, $domains, true ) ) {
				return $idp;
			}
		}

		return null;
	}

	// ── Write ───────────────────────────────────────────────────────────────

	/**
	 * Save/update an IdP configuration. Inserts if new id, updates if existing.
	 *
	 * @param array<string, mixed> $idp
	 */
	public static function save( array $idp ): void {
		$all   = self::all();
		$found = false;

		foreach ( $all as $i => $existing ) {
			if ( ( $existing['id'] ?? '' ) === ( $idp['id'] ?? '' ) ) {
				$all[ $i ] = $idp;
				$found     = true;
				break;
			}
		}

		if ( ! $found ) {
			$all[] = $idp;
		}

		update_option( self::OPTION_KEY, array_values( $all ) );
	}

	/**
	 * Delete an IdP configuration by id.
	 */
	public static function delete( string $id ): bool {
		$all     = self::all();
		$filtered = array_filter( $all, static fn( array $idp ) => ( $idp['id'] ?? '' ) !== $id );

		if ( count( $filtered ) === count( $all ) ) {
			return false;
		}

		update_option( self::OPTION_KEY, array_values( $filtered ) );
		return true;
	}

	// ── Sanitization ────────────────────────────────────────────────────────

	/**
	 * Sanitize a raw IdP configuration array from the REST API.
	 *
	 * @param array<string, mixed> $raw
	 * @return array<string, mixed>
	 */
	public static function sanitize( array $raw ): array {
		$protocol = in_array( $raw['protocol'] ?? '', [ 'oidc', 'saml' ], true )
			? $raw['protocol']
			: 'oidc';

		$domain_mapping = [];
		if ( ! empty( $raw['domain_mapping'] ) && is_array( $raw['domain_mapping'] ) ) {
			foreach ( $raw['domain_mapping'] as $d ) {
				$clean = sanitize_text_field( (string) $d );
				if ( $clean !== '' ) {
					$domain_mapping[] = strtolower( $clean );
				}
			}
		}

		$role_mapping = [];
		if ( ! empty( $raw['role_mapping'] ) && is_array( $raw['role_mapping'] ) ) {
			foreach ( $raw['role_mapping'] as $group => $role ) {
				$g = sanitize_text_field( (string) $group );
				$r = sanitize_text_field( (string) $role );
				if ( $g !== '' && $r !== '' ) {
					$role_mapping[ $g ] = $r;
				}
			}
		}

		return [
			'id'                     => ! empty( $raw['id'] ) ? sanitize_text_field( $raw['id'] ) : wp_generate_uuid4(),
			'provider_name'          => sanitize_text_field( $raw['provider_name'] ?? '' ),
			'protocol'               => $protocol,
			'client_id'              => sanitize_text_field( $raw['client_id'] ?? '' ),
			'client_secret'          => sanitize_text_field( $raw['client_secret'] ?? '' ),
			'issuer'                 => esc_url_raw( $raw['issuer'] ?? '' ),
			'entity_id'              => sanitize_text_field( $raw['entity_id'] ?? '' ),
			'certificate'            => sanitize_textarea_field( $raw['certificate'] ?? '' ),
			'authorization_endpoint' => esc_url_raw( $raw['authorization_endpoint'] ?? '' ),
			'token_endpoint'         => esc_url_raw( $raw['token_endpoint'] ?? '' ),
			'userinfo_endpoint'      => esc_url_raw( $raw['userinfo_endpoint'] ?? '' ),
			'jwks_uri'               => esc_url_raw( $raw['jwks_uri'] ?? '' ),
			'sso_url'                => esc_url_raw( $raw['sso_url'] ?? '' ),
			'domain_mapping'         => $domain_mapping,
			'role_mapping'           => $role_mapping,
			'enabled'                => ! empty( $raw['enabled'] ),
		];
	}
}
