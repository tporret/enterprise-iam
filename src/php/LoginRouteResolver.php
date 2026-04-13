<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginRouteResolver {

	/**
	 * Resolve the login outcome for an identity in a given blog context.
	 *
	 * @return array<string, mixed>
	 */
	public function resolve( string $email, ?int $blog_id = null, string $redirect_to = '' ): array {
		$email = sanitize_email( $email );
		if ( ! is_email( $email ) ) {
			return array(
				'email' => $email,
				'domain' => '',
				'blog_id' => (int) ( $blog_id ?? get_current_blog_id() ),
				'outcome' => 'local',
				'reason' => 'invalid_email',
				'redirect_url' => '',
				'redirect_to' => '',
				'matched_provider_id' => '',
				'matched_provider_name' => '',
				'matched_protocol' => '',
				'user_exists_on_site' => false,
				'user_id' => 0,
				'user_bound_provider_id' => '',
			);
		}

		$blog_id = $blog_id ?? get_current_blog_id();

		return $this->with_blog(
			$blog_id,
			function () use ( $email, $redirect_to ): array {
				$parts  = explode( '@', $email );
				$domain = strtolower( $parts[1] ?? '' );
				$idp    = CurrentSiteIdpManager::find_by_domain( $domain );
				$wp_user = get_user_by( 'email', $email );

				if ( is_multisite() && $wp_user instanceof \WP_User && ! is_user_member_of_blog( $wp_user->ID, get_current_blog_id() ) ) {
					$wp_user = null;
				}

				$result = array(
					'email' => $email,
					'domain' => $domain,
					'blog_id' => get_current_blog_id(),
					'outcome' => 'local',
					'reason' => 'domain_not_mapped',
					'redirect_url' => '',
					'redirect_to' => $this->validated_redirect_target( $redirect_to ),
					'matched_provider_id' => '',
					'matched_provider_name' => '',
					'matched_protocol' => '',
					'user_exists_on_site' => $wp_user instanceof \WP_User,
					'user_id' => $wp_user instanceof \WP_User ? $wp_user->ID : 0,
					'user_bound_provider_id' => $wp_user instanceof \WP_User ? (string) get_user_meta( $wp_user->ID, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ), true ) : '',
				);

				if ( ! $idp ) {
					return $result;
				}

				$result['matched_provider_id']   = (string) ( $idp['id'] ?? '' );
				$result['matched_provider_name'] = (string) ( $idp['provider_name'] ?? '' );
				$result['matched_protocol']      = (string) ( $idp['protocol'] ?? '' );

				if ( $wp_user instanceof \WP_User ) {
					if ( '' === $result['user_bound_provider_id'] ) {
						$result['reason'] = 'local_account_on_sso_domain';
						return $result;
					}
				}

				$result['outcome']      = 'sso';
				$result['reason']       = 'domain_matched_provider';
				$result['redirect_url'] = $this->build_redirect_url( $idp );

				return $result;
			}
		);
	}

	/**
	 * @param array<string, mixed> $idp
	 */
	public function build_redirect_url( array $idp ): string {
		if ( 'oidc' === ( $idp['protocol'] ?? '' ) ) {
			return add_query_arg(
				array(
					'idp_id' => $idp['id'],
				),
				rest_url( 'enterprise-auth/v1/oidc/login' )
			);
		}

		return add_query_arg(
			array(
				'idp_id' => $idp['id'],
			),
			rest_url( 'enterprise-auth/v1/saml/login' )
		);
	}

	private function validated_redirect_target( string $redirect_to ): string {
		$redirect_to = trim( $redirect_to );

		if ( '' === $redirect_to ) {
			return '';
		}

		return wp_validate_redirect( $redirect_to, '' );
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
}