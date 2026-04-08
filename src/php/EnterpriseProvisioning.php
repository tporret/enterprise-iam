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
 *
 * Security controls:
 *  1. Break-glass admin isolation — admin accounts are never managed via SSO.
 *  2. Strict account binding — uses the IdP's immutable UID (OIDC sub / SAML NameID)
 *     as the primary key after first login, not email.
 *  3. JIT role ceiling — caps the maximum role SSO can assign.
 */
final class EnterpriseProvisioning {

	private const META_SSO_PROVIDER = '_enterprise_auth_sso_provider';
	private const META_IDP_UID      = '_enterprise_auth_idp_uid';
	private const META_IDP_ISSUER   = '_enterprise_auth_idp_issuer';

	/**
	 * Ordered role hierarchy from highest to lowest privilege.
	 * Used to enforce the role ceiling.
	 */
	private const ROLE_HIERARCHY = array(
		'administrator' => 5,
		'editor'        => 4,
		'author'        => 3,
		'contributor'   => 2,
		'subscriber'    => 1,
	);

	/**
	 * Provision the user and log them in.
	 *
	 * @param array $idp        IdP config from IdpManager.
	 * @param array $attributes Parsed identity attributes (email, first_name, last_name, groups, idp_uid).
	 * @return true|\WP_Error
	 */
	public static function provision_and_login( array $idp, array $attributes ) {
		$email          = sanitize_email( $attributes['email'] ?? '' );
		$idp_uid        = sanitize_text_field( $attributes['idp_uid'] ?? '' );
		$idp_id         = $idp['id'] ?? '';
		$idp_issuer     = sanitize_text_field( $attributes['idp_issuer'] ?? '' );
		$email_verified = ! empty( $attributes['email_verified'] );

		if ( ! is_email( $email ) ) {
			return new \WP_Error( 'enterprise_provision', 'No valid email address in identity assertion.' );
		}

		// ── 1. Primary lookup: immutable IdP UID ────────────────────────
		$user = self::find_user_by_idp_uid( $idp_id, $idp_uid );

		if ( $user ) {
			// ── Break-glass: reject SSO for administrators / user ID 1 ──
			$admin_check = self::reject_if_admin( $user );
			if ( is_wp_error( $admin_check ) ) {
				return $admin_check;
			}

			// Verify the issuer hasn't changed (iss+sub composite check).
			if ( '' !== $idp_issuer ) {
				$stored_issuer = get_user_meta( $user->ID, self::META_IDP_ISSUER, true );
				if ( '' === $stored_issuer ) {
					// Back-fill issuer for accounts created before this check.
					update_user_meta( $user->ID, self::META_IDP_ISSUER, $idp_issuer );
				} elseif ( $stored_issuer !== $idp_issuer ) {
					return new \WP_Error(
						'enterprise_provision',
						'Issuer mismatch: the identity provider issuer does not match the bound account. Login blocked.'
					);
				}
			}
		} elseif ( '' !== $idp_uid ) {
			// ── 2. First-time binding: fall back to email lookup ─────────
			// Require a verified email before binding an IdP identity to an
			// existing WordPress account. Without this check, an attacker who
			// controls an IdP could claim any email address and hijack the
			// linked WordPress account.
			if ( ! $email_verified ) {
				return new \WP_Error(
					'enterprise_provision',
					'Your identity provider did not confirm your email address (email_verified). Login blocked for account safety.'
				);
			}

			$user = get_user_by( 'email', $email );

			if ( $user ) {
				// Break-glass: reject SSO for administrators / user ID 1.
				$admin_check = self::reject_if_admin( $user );
				if ( is_wp_error( $admin_check ) ) {
					return $admin_check;
				}

				$existing_provider = get_user_meta( $user->ID, self::META_SSO_PROVIDER, true );

				if ( empty( $existing_provider ) ) {
					return new \WP_Error(
						'enterprise_provision',
						'A local account already exists with this email address. SSO login is not permitted for local accounts.'
					);
				}

				if ( $existing_provider !== $idp_id ) {
					return new \WP_Error(
						'enterprise_provision',
						'This account is managed by a different identity provider.'
					);
				}

				// The user exists and belongs to this IdP but has no UID stored yet.
				// Bind the immutable UID and issuer now.
				$stored_uid = get_user_meta( $user->ID, self::META_IDP_UID, true );
				if ( '' === $stored_uid ) {
					update_user_meta( $user->ID, self::META_IDP_UID, $idp_uid );
					if ( '' !== $idp_issuer ) {
						update_user_meta( $user->ID, self::META_IDP_ISSUER, $idp_issuer );
					}
				} elseif ( $stored_uid !== $idp_uid ) {
					// UID mismatch — possible IdP spoofing.
					return new \WP_Error(
						'enterprise_provision',
						'Identity mismatch: the IdP unique identifier does not match the bound account. Login blocked.'
					);
				}
			}
		} else {
			// No idp_uid provided — legacy email-only lookup.
			// Without an immutable UID, email is the only identifier.
			// Require verified email for this unsafe path.
			if ( ! $email_verified ) {
				return new \WP_Error(
					'enterprise_provision',
					'Your identity provider did not confirm your email address (email_verified). Login blocked for account safety.'
				);
			}

			$user = get_user_by( 'email', $email );

			if ( $user ) {
				$admin_check = self::reject_if_admin( $user );
				if ( is_wp_error( $admin_check ) ) {
					return $admin_check;
				}

				$existing_provider = get_user_meta( $user->ID, self::META_SSO_PROVIDER, true );

				if ( empty( $existing_provider ) ) {
					return new \WP_Error(
						'enterprise_provision',
						'A local account already exists with this email address. SSO login is not permitted for local accounts.'
					);
				}

				if ( $existing_provider !== $idp_id ) {
					return new \WP_Error(
						'enterprise_provision',
						'This account is managed by a different identity provider.'
					);
				}
			}
		}

		// ── 3. New user creation ────────────────────────────────────────
		if ( ! $user ) {
			// Never create a WordPress account from an unverified email.
			if ( ! $email_verified ) {
				return new \WP_Error(
					'enterprise_provision',
					'Cannot create an account: the identity provider did not confirm your email address (email_verified).'
				);
			}

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
			update_user_meta( $user_id, self::META_SSO_PROVIDER, $idp_id );
			if ( '' !== $idp_uid ) {
				update_user_meta( $user_id, self::META_IDP_UID, $idp_uid );
			}
			if ( '' !== $idp_issuer ) {
				update_user_meta( $user_id, self::META_IDP_ISSUER, $idp_issuer );
			}
		}

		// Map IdP groups → WP roles (only for SSO-provisioned users).
		self::apply_role_mapping( $user, $idp, (array) ( $attributes['groups'] ?? array() ) );

		// ── Session control ─────────────────────────────────────────────
		// Record the SSO login timestamp for session timeout enforcement.
		update_user_meta( $user->ID, '_enterprise_auth_sso_login_at', time() );

		// If the IdP provided a session expiry (SAML SessionNotOnOrAfter),
		// store it so the session-check hook can honour it.
		$session_expires = $attributes['session_not_on_or_after'] ?? 0;
		if ( $session_expires > 0 ) {
			update_user_meta( $user->ID, '_enterprise_auth_session_expires', (int) $session_expires );
		}

		// Use a browser-session cookie (not persistent "remember me") so
		// closing the browser ends the session. The `auth_cookie_expiration`
		// filter in Core.php further caps the server-side lifetime.
		wp_set_auth_cookie( $user->ID, false );
		do_action( 'wp_login', $user->user_login, $user );

		return true;
	}

	/**
	 * Break-glass admin isolation.
	 *
	 * User ID 1 and any user with the Administrator role must never be
	 * managed via SSO. If the IdP goes down or is compromised, the local
	 * admin can still log in with a password or passkey.
	 *
	 * @return true|\WP_Error
	 */
	private static function reject_if_admin( \WP_User $user ) {
		if ( 1 === $user->ID || in_array( 'administrator', (array) $user->roles, true ) ) {
			return new \WP_Error(
				'enterprise_provision',
				'Administrator accounts cannot be managed via SSO. Please log in with your local password or passkey.'
			);
		}
		return true;
	}

	/**
	 * Look up a WordPress user by the immutable IdP unique identifier.
	 *
	 * @return \WP_User|null
	 */
	private static function find_user_by_idp_uid( string $idp_id, string $idp_uid ): ?\WP_User {
		if ( '' === $idp_uid || '' === $idp_id ) {
			return null;
		}

		$users = get_users(
			array(
				'meta_query' => array(
					'relation' => 'AND',
					array(
						'key'   => self::META_IDP_UID,
						'value' => $idp_uid,
					),
					array(
						'key'   => self::META_SSO_PROVIDER,
						'value' => $idp_id,
					),
				),
				'number'     => 1,
				'fields'     => 'all',
			)
		);

		return ! empty( $users ) ? $users[0] : null;
	}

	/**
	 * Map IdP group claims to a WordPress role.
	 *
	 * Priority: exact group match → wildcard "*" mapping → no change.
	 * The resolved role is capped at the configured role ceiling to prevent
	 * privilege escalation via rogue IdP payloads.
	 */
	private static function apply_role_mapping( \WP_User $user, array $idp, array $groups ): void {
		$mapping = $idp['role_mapping'] ?? array();

		if ( empty( $mapping ) ) {
			return;
		}

		$resolved_role = null;

		// Try to match an incoming group claim to a mapped role.
		foreach ( $groups as $group ) {
			$group_lower = strtolower( (string) $group );
			foreach ( $mapping as $idp_group => $wp_role ) {
				if ( strtolower( $idp_group ) === $group_lower ) {
					$resolved_role = $wp_role;
					break 2;
				}
			}
		}

		// No group matched — use the wildcard "*" mapping if configured.
		if ( null === $resolved_role && isset( $mapping['*'] ) ) {
			$resolved_role = $mapping['*'];
		}

		if ( null === $resolved_role ) {
			return;
		}

		// Enforce the role ceiling.
		$resolved_role = self::cap_role( $resolved_role );

		$user->set_role( $resolved_role );
	}

	/**
	 * Cap a role at the configured role ceiling.
	 *
	 * If the requested role is more privileged than the ceiling, return the
	 * ceiling role instead. Unknown roles are passed through unchanged.
	 */
	private static function cap_role( string $role ): string {
		$settings = SettingsController::read();
		$ceiling  = $settings['role_ceiling'] ?? 'editor';

		$role_level    = self::ROLE_HIERARCHY[ $role ] ?? 0;
		$ceiling_level = self::ROLE_HIERARCHY[ $ceiling ] ?? self::ROLE_HIERARCHY['editor'];

		if ( $role_level > $ceiling_level ) {
			return $ceiling;
		}

		return $role;
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
