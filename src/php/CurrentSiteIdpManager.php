<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class CurrentSiteIdpManager {

	public static function uses_network_control_plane(): bool {
		return NetworkMode::is_network_idp_control_plane_active();
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function all(): array {
		return self::all_for_blog( get_current_blog_id() );
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function all_for_blog( int $blog_id ): array {
		return self::with_blog(
			$blog_id,
			static function (): array {
				if ( ! self::uses_network_control_plane() ) {
					return self::site_idp_store()->all();
				}

				$assignment = SiteAssignmentManager::read_for_current_site();
				if ( empty( $assignment['assigned_idp_ids'] ) ) {
					return array();
				}

				$network_idps = array();
				foreach ( self::network_idp_store()->all() as $idp ) {
					$network_idps[ (string) ( $idp['id'] ?? '' ) ] = $idp;
				}

				$resolved = array();
				foreach ( $assignment['assigned_idp_ids'] as $idp_id ) {
					if ( isset( $network_idps[ $idp_id ] ) ) {
						$resolved[] = $network_idps[ $idp_id ];
					}
				}

				return $resolved;
			}
		);
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public static function find( string $id ): ?array {
		return self::find_for_blog( get_current_blog_id(), $id );
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public static function find_for_blog( int $blog_id, string $id ): ?array {
		foreach ( self::all_for_blog( $blog_id ) as $idp ) {
			if ( ( $idp['id'] ?? '' ) === $id ) {
				return $idp;
			}
		}

		return null;
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public static function find_by_domain( string $domain ): ?array {
		return self::find_by_domain_for_blog( get_current_blog_id(), $domain );
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public static function find_by_domain_for_blog( int $blog_id, string $domain ): ?array {
		$domain = strtolower( trim( $domain ) );

		foreach ( self::all_for_blog( $blog_id ) as $idp ) {
			if ( empty( $idp['enabled'] ) ) {
				continue;
			}

			$domains = array_map( 'strtolower', (array) ( $idp['domain_mapping'] ?? array() ) );
			if ( in_array( $domain, $domains, true ) ) {
				return $idp;
			}
		}

		return null;
	}

	private static function with_blog( int $blog_id, callable $callback ): mixed {
		if ( ! is_multisite() || $blog_id <= 0 || get_current_blog_id() === $blog_id ) {
			return $callback();
		}

		switch_to_blog( $blog_id );
		try {
			return $callback();
		} finally {
			restore_current_blog();
		}
	}

	private static function site_idp_store(): IdpRepositoryManager {
		return new IdpRepositoryManager( new SiteIdpAdapter() );
	}

	private static function network_idp_store(): IdpRepositoryManager {
		return new IdpRepositoryManager( new NetworkIdpAdapter(), 'network' );
	}
}