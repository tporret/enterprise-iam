<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shared policy for deciding whether a WordPress auth session may be created.
 */
final class SessionCreationGuard {

	/**
	 * @return true|\WP_Error
	 */
	public static function may_create_session( \WP_User $user ) {
		if ( self::is_scim_suspended( $user->ID ) ) {
			return self::suspension_error();
		}

		return true;
	}

	public static function is_scim_suspended( int $user_id ): bool {
		$network_suspended = get_user_meta( $user_id, SiteMetaKeys::NETWORK_SCIM_SUSPENDED, true );
		if ( 'true' === $network_suspended ) {
			return true;
		}

		$suspended = get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ), true );

		return 'true' === $suspended;
	}

	public static function suspension_error(): \WP_Error {
		return new \WP_Error(
			'account_suspended',
			__( 'Account suspended by Identity Provider.', 'enterprise-auth' )
		);
	}
}