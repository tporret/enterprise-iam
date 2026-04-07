<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Just-In-Time (JIT) provisioning for SSO-authenticated users.
 *
 * Given validated identity attributes (SAML or OIDC), this class finds or
 * creates a WordPress user, maps IdP roles, and logs them in.
 */
final class EnterpriseProvisioning {

	/**
	 * Provision the user and log them in.
	 *
	 * @param array $idp        IdP config from IdpManager.
	 * @param array $attributes Parsed identity attributes (email, first_name, last_name, groups).
	 * @return true|\WP_Error
	 */
	public static function provision_and_login( array $idp, array $attributes ) {
		$email = sanitize_email( $attributes['email'] ?? '' );

		if ( ! is_email( $email ) ) {
			return new \WP_Error( 'enterprise_provision', 'No valid email address in identity assertion.' );
		}

		$user = get_user_by( 'email', $email );

		if ( ! $user ) {
			$username   = self::generate_username( $email );
			$password   = wp_generate_password( 32, true, true );
			$first_name = sanitize_text_field( $attributes['first_name'] ?? '' );
			$last_name  = sanitize_text_field( $attributes['last_name'] ?? '' );
			$display    = trim( "$first_name $last_name" );
			if ( '' === $display ) {
				$display = $username;
			}

			$user_id = wp_insert_user(
				array(
					'user_login'   => $username,
					'user_email'   => $email,
					'user_pass'    => $password,
					'first_name'   => $first_name,
					'last_name'    => $last_name,
					'display_name' => $display,
					'role'         => 'subscriber',
				)
			);

			if ( is_wp_error( $user_id ) ) {
				return $user_id;
			}

			$user = get_user_by( 'id', $user_id );
			update_user_meta( $user_id, '_enterprise_auth_sso_provider', $idp['id'] ?? '' );
		}

		// Map IdP groups → WP roles.
		self::apply_role_mapping( $user, $idp, (array) ( $attributes['groups'] ?? array() ) );

		// Log the user in.
		wp_set_auth_cookie( $user->ID, true );
		do_action( 'wp_login', $user->user_login, $user );

		return true;
	}

	/**
	 * Map IdP group claims to a WordPress role.
	 *
	 * Priority: exact group match → wildcard "*" mapping → no change.
	 */
	private static function apply_role_mapping( \WP_User $user, array $idp, array $groups ): void {
		$mapping = $idp['role_mapping'] ?? array();

		if ( empty( $mapping ) ) {
			return;
		}

		// Try to match an incoming group claim to a mapped role.
		foreach ( $groups as $group ) {
			$group_lower = strtolower( (string) $group );
			foreach ( $mapping as $idp_group => $wp_role ) {
				if ( strtolower( $idp_group ) === $group_lower ) {
					$user->set_role( $wp_role );
					return;
				}
			}
		}

		// No group matched — use the wildcard "*" mapping if configured.
		if ( isset( $mapping['*'] ) ) {
			$user->set_role( $mapping['*'] );
		}
	}

	/**
	 * Derive a unique username from an email address.
	 */
	private static function generate_username( string $email ): string {
		$base = sanitize_user( strtok( $email, '@' ), true );

		if ( ! username_exists( $base ) ) {
			return $base;
		}

		$i = 2;
		while ( username_exists( $base . $i ) ) {
			++$i;
		}

		return $base . $i;
	}
}
