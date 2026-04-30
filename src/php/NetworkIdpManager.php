<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class NetworkIdpManager {

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function all(): array {
		return self::repository_manager()->all();
	}

	public static function has_any(): bool {
		return self::repository_manager()->hasAny();
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public static function find( string $id ): ?array {
		return self::repository_manager()->find( $id );
	}

	/**
	 * @param array<string, mixed> $idp
	 * @return true|\WP_Error
	 */
	public static function save( array $idp ) {
		return self::repository_manager()->save( $idp );
	}

	public static function delete( string $id ): bool {
		return self::repository_manager()->delete( $id );
	}

	private static function repository_manager(): IdpRepositoryManager {
		return new IdpRepositoryManager( new NetworkIdpAdapter(), 'network' );
	}
}