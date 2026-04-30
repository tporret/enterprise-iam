<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class UserIdentityRepository {

	public function providerId( int $user_id ): string {
		return (string) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ), true );
	}

	public function idpUid( int $user_id ): string {
		return (string) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::IDP_UID ), true );
	}

	public function issuer( int $user_id ): string {
		return (string) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::IDP_ISSUER ), true );
	}

	public function scimExternalId( int $user_id ): string {
		return (string) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ), true );
	}

	public function isSiteSuspended( int $user_id ): bool {
		return 'true' === get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ), true );
	}

	public function isNetworkSuspended( int $user_id ): bool {
		return 'true' === get_user_meta( $user_id, SiteMetaKeys::NETWORK_SCIM_SUSPENDED, true );
	}

	public function lastSsoLoginAt( int $user_id ): int {
		return (int) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SSO_LOGIN_AT ), true );
	}

	public function sessionExpiresAt( int $user_id ): int {
		return (int) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SESSION_EXPIRES ), true );
	}

	public function isStepUpRequired( int $user_id ): bool {
		return (bool) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::PASSKEY_STEP_UP_REQUIRED ), true );
	}

	public function setIssuer( int $user_id, string $issuer ): void {
		if ( '' === $issuer ) {
			return;
		}

		update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::IDP_ISSUER ), $issuer );
	}

	public function bindToProvider( int $user_id, string $provider_id, string $idp_uid, string $issuer ): void {
		update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ), $provider_id );

		if ( '' !== $idp_uid ) {
			update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::IDP_UID ), $idp_uid );
		}

		if ( '' !== $issuer ) {
			update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::IDP_ISSUER ), $issuer );
		}
	}

	public function touchSsoLogin( int $user_id, int $timestamp ): void {
		update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SSO_LOGIN_AT ), $timestamp );
	}

	public function setSessionExpires( int $user_id, int $expires_at ): void {
		update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SESSION_EXPIRES ), $expires_at );
	}

	public function storeOidcIdToken( int $user_id, string $encrypted_token ): void {
		update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::OIDC_ID_TOKEN ), $encrypted_token );
	}

	public function clearOidcIdToken( int $user_id ): void {
		delete_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::OIDC_ID_TOKEN ) );
	}

	/**
	 * @return array<int|string, mixed>
	 */
	public function allMeta( int $user_id ): array {
		$all_meta = get_user_meta( $user_id );

		return is_array( $all_meta ) ? $all_meta : array();
	}

	public function findUserByBinding( string $provider_id, string $idp_uid ): ?\WP_User {
		if ( '' === $idp_uid || '' === $provider_id ) {
			return null;
		}

		$users = get_users(
			array(
				'meta_query' => array(
					'relation' => 'AND',
					array(
						'key' => SiteMetaKeys::key( SiteMetaKeys::IDP_UID ),
						'value' => $idp_uid,
					),
					array(
						'key' => SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ),
						'value' => $provider_id,
					),
				),
				'number' => 1,
				'fields' => 'all',
			)
		);

		return ! empty( $users ) && $users[0] instanceof \WP_User ? $users[0] : null;
	}

	/**
	 * @return array<string, mixed>
	 */
	public function readStateSnapshot( int $user_id ): array {
		return array(
			'provider_id' => $this->providerId( $user_id ),
			'idp_uid' => $this->idpUid( $user_id ),
			'issuer' => $this->issuer( $user_id ),
			'scim_external_id' => $this->scimExternalId( $user_id ),
			'suspended_site' => $this->isSiteSuspended( $user_id ),
			'suspended_network' => $this->isNetworkSuspended( $user_id ),
			'last_sso_login_at' => $this->lastSsoLoginAt( $user_id ),
			'session_expires_at' => $this->sessionExpiresAt( $user_id ),
			'step_up_required' => $this->isStepUpRequired( $user_id ),
		);
	}
}
