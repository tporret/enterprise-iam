<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pure policy decisions for SSO-bound account controls.
 */
final class SsoAccountPolicy {

	/**
	 * User ID 1 remains break-glass and is never treated as SSO-bound.
	 */
	public function isSsoBound( \WP_User $user ): bool {
		if ( 1 === $user->ID ) {
			return false;
		}

		if ( 'true' === get_user_meta( $user->ID, SiteMetaKeys::NETWORK_SCIM_SUSPENDED, true ) ) {
			return true;
		}

		$idp_uid = get_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::IDP_UID ), true );
		if ( '' !== $idp_uid ) {
			return true;
		}

		$scim_id = get_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ), true );
		if ( '' !== $scim_id ) {
			return true;
		}

		return false;
	}

	public function canResetPassword( \WP_User $user ): bool {
		return ! $this->isSsoBound( $user );
	}

	public function canMutateProfile( \WP_User $user ): bool {
		return ! $this->isSsoBound( $user );
	}

	public function canUseLocalPasswordLogin( \WP_User $user ): bool {
		return ! $this->isSsoBound( $user );
	}
}
