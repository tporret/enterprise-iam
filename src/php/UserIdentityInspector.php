<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class UserIdentityInspector {

	/**
	 * @var array<int, array<string, array<string, mixed>>>
	 */
	private array $provider_map_cache = array();

	/**
	 * Inspect one user in the current or provided site context.
	 *
	 * @param int|\WP_User $user User object or ID.
	 * @return array<string, mixed>
	 */
	public function inspect( int|\WP_User $user, ?int $blog_id = null ): array {
		$user = $user instanceof \WP_User ? $user : get_userdata( $user );

		if ( ! ( $user instanceof \WP_User ) ) {
			return $this->empty_result();
		}

		$results = $this->inspect_many( array( $user->ID ), $blog_id );

		return $results[ $user->ID ] ?? $this->empty_result();
	}

	/**
	 * Inspect many users in one site context.
	 *
	 * @param array<int> $user_ids User IDs.
	 * @return array<int, array<string, mixed>>
	 */
	public function inspect_many( array $user_ids, ?int $blog_id = null ): array {
		$blog_id = $blog_id ?? get_current_blog_id();
		$user_ids = array_values(
			array_unique(
				array_filter(
					array_map( 'intval', $user_ids ),
					static fn( int $user_id ): bool => $user_id > 0
				)
			)
		);

		if ( array() === $user_ids ) {
			return array();
		}

		$provider_map       = $this->provider_map_for_blog( $blog_id );
		$passkey_summaries  = CredentialRepository::passkey_summaries_for_users( $user_ids );
		$results            = array();

		foreach ( $user_ids as $user_id ) {
			$user = get_userdata( $user_id );
			if ( ! ( $user instanceof \WP_User ) ) {
				continue;
			}

			$site_state = $this->read_site_state( $user->ID, $blog_id );
			$provider   = $site_state['provider_id'] ? ( $provider_map[ $site_state['provider_id'] ] ?? null ) : null;
			$passkeys   = $passkey_summaries[ $user->ID ] ?? array(
				'total' => 0,
				'compliant' => 0,
				'legacy_non_compliant' => 0,
				'last_used_at' => '',
			);

			$has_sso  = '' !== $site_state['provider_id'] || '' !== $site_state['idp_uid'] || '' !== $site_state['issuer'];
			$has_scim = '' !== $site_state['scim_external_id'] || $site_state['suspended_site'] || $site_state['suspended_network'];

			$results[ $user->ID ] = array(
				'blog_id' => $blog_id,
				'identity_source' => $this->identity_source( $has_sso, $has_scim ),
				'provider_id' => $site_state['provider_id'],
				'provider_name' => (string) ( $provider['provider_name'] ?? '' ),
				'protocol' => (string) ( $provider['protocol'] ?? '' ),
				'idp_uid_masked' => $this->mask_identifier( $site_state['idp_uid'] ),
				'issuer' => $site_state['issuer'],
				'scim_external_id_masked' => $this->mask_identifier( $site_state['scim_external_id'] ),
				'suspended_site' => $site_state['suspended_site'],
				'suspended_network' => $site_state['suspended_network'],
				'last_sso_login_at' => $site_state['last_sso_login_at'],
				'session_expires_at' => $site_state['session_expires_at'],
				'passkeys' => array(
					'total' => (int) ( $passkeys['total'] ?? 0 ),
					'compliant' => (int) ( $passkeys['compliant'] ?? 0 ),
					'legacy_non_compliant' => (int) ( $passkeys['legacy_non_compliant'] ?? 0 ),
					'last_used_at' => $this->mysql_to_timestamp( (string) ( $passkeys['last_used_at'] ?? '' ) ),
					'step_up_required' => $site_state['step_up_required'],
				),
			);
		}

		return $results;
	}

	/**
	 * @return array<string, mixed>
	 */
	private function read_site_state( int $user_id, int $blog_id ): array {
		return $this->with_blog(
			$blog_id,
			static function () use ( $user_id ): array {
				return array(
					'provider_id' => (string) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ), true ),
					'idp_uid' => (string) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::IDP_UID ), true ),
					'issuer' => (string) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::IDP_ISSUER ), true ),
					'scim_external_id' => (string) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ), true ),
					'suspended_site' => 'true' === get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ), true ),
					'suspended_network' => 'true' === get_user_meta( $user_id, SiteMetaKeys::NETWORK_SCIM_SUSPENDED, true ),
					'last_sso_login_at' => (int) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SSO_LOGIN_AT ), true ),
					'session_expires_at' => (int) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SESSION_EXPIRES ), true ),
					'step_up_required' => (bool) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::PASSKEY_STEP_UP_REQUIRED ), true ),
				);
			}
		);
	}

	/**
	 * @return array<string, array<string, mixed>>
	 */
	private function provider_map_for_blog( int $blog_id ): array {
		if ( isset( $this->provider_map_cache[ $blog_id ] ) ) {
			return $this->provider_map_cache[ $blog_id ];
		}

		$providers = CurrentSiteIdpManager::all_for_blog( $blog_id );
		$map       = array();

		foreach ( $providers as $provider ) {
			$id = (string) ( $provider['id'] ?? '' );
			if ( '' === $id ) {
				continue;
			}

			$map[ $id ] = $provider;
		}

		$this->provider_map_cache[ $blog_id ] = $map;

		return $map;
	}

	private function identity_source( bool $has_sso, bool $has_scim ): string {
		if ( $has_sso && $has_scim ) {
			return 'mixed';
		}

		if ( $has_sso ) {
			return 'sso';
		}

		if ( $has_scim ) {
			return 'scim';
		}

		return 'local';
	}

	private function mask_identifier( string $value ): string {
		$value = trim( $value );

		if ( '' === $value ) {
			return '';
		}

		$length = strlen( $value );
		if ( $length <= 4 ) {
			return substr( $value, 0, 1 ) . str_repeat( '*', max( 0, $length - 2 ) ) . substr( $value, -1 );
		}

		if ( $length <= 8 ) {
			return substr( $value, 0, 2 ) . '...' . substr( $value, -2 );
		}

		return substr( $value, 0, 3 ) . '...' . substr( $value, -3 );
	}

	private function mysql_to_timestamp( string $value ): int {
		$value = trim( $value );

		if ( '' === $value ) {
			return 0;
		}

		$timestamp = strtotime( $value . ' UTC' );

		return false === $timestamp ? 0 : (int) $timestamp;
	}

	private function with_blog( int $blog_id, callable $callback ): mixed {
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

	/**
	 * @return array<string, mixed>
	 */
	private function empty_result(): array {
		return array(
			'blog_id' => 0,
			'identity_source' => 'local',
			'provider_id' => '',
			'provider_name' => '',
			'protocol' => '',
			'idp_uid_masked' => '',
			'issuer' => '',
			'scim_external_id_masked' => '',
			'suspended_site' => false,
			'suspended_network' => false,
			'last_sso_login_at' => 0,
			'session_expires_at' => 0,
			'passkeys' => array(
				'total' => 0,
				'compliant' => 0,
				'legacy_non_compliant' => 0,
				'last_used_at' => 0,
				'step_up_required' => false,
			),
		);
	}
}