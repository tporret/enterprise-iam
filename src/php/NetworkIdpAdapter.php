<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class NetworkIdpAdapter implements IdpRepositoryInterface {

	private const OPTION_KEY = 'enterprise_auth_network_idps';

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public function readAllRaw(): array {
		$raw = get_site_option( self::OPTION_KEY, array() );

		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * @param array<int, array<string, mixed>> $idps
	 */
	public function writeAll( array $idps ): void {
		update_site_option( self::OPTION_KEY, array_values( $idps ) );
	}
}
