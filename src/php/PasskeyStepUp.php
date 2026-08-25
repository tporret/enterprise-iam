<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PasskeyStepUp {

	private const TRANSIENT_PREFIX = 'ea_passkey_stepup_verified_';
	private const TTL              = 10 * MINUTE_IN_SECONDS;

	/**
	 * @var array<int, array{method:string, pattern:string}>
	 */
	private const HIGH_RISK_REST_ROUTES = array(
		array(
			'method'  => 'POST',
			'pattern' => '#^/enterprise-auth/v1/settings$#',
		),
		array(
			'method'  => 'POST',
			'pattern' => '#^/enterprise-auth/v1/settings/scim-token$#',
		),
		array(
			'method'  => 'POST',
			'pattern' => '#^/enterprise-auth/v1/idps$#',
		),
		array(
			'method'  => 'DELETE',
			'pattern' => '#^/enterprise-auth/v1/idps/[a-f0-9-]+$#',
		),
		array(
			'method'  => 'POST',
			'pattern' => '#^/enterprise-auth/v1/network/defaults$#',
		),
		array(
			'method'  => 'POST',
			'pattern' => '#^/enterprise-auth/v1/network/idps$#',
		),
		array(
			'method'  => 'DELETE',
			'pattern' => '#^/enterprise-auth/v1/network/idps/[a-f0-9-]+$#',
		),
		array(
			'method'  => 'POST',
			'pattern' => '#^/enterprise-auth/v1/network/sites/\d+/assignments$#',
		),
	);

	public static function is_high_risk_rest_request( \WP_REST_Request $request ): bool {
		$route  = $request->get_route();
		$method = strtoupper( $request->get_method() );

		foreach ( self::HIGH_RISK_REST_ROUTES as $protected_route ) {
			if ( $method !== $protected_route['method'] ) {
				continue;
			}

			if ( 1 === preg_match( $protected_route['pattern'], $route ) ) {
				return true;
			}
		}

		return false;
	}

	public static function is_verified( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}

		return (bool) get_transient( self::transient_key( $user_id ) );
	}

	public static function mark_verified( int $user_id ): void {
		if ( $user_id <= 0 ) {
			return;
		}

		set_transient( self::transient_key( $user_id ), time(), self::TTL );
	}

	public static function ttl(): int {
		return self::TTL;
	}

	private static function transient_key( int $user_id ): string {
		$key = self::TRANSIENT_PREFIX . $user_id;

		if ( ! is_multisite() ) {
			return $key;
		}

		return 'ea_' . get_current_blog_id() . '_' . $key;
	}
}
