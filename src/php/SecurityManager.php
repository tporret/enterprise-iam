<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Security Hardening Manager.
 *
 * Locks down legacy WordPress attack surface on every request.
 */
final class SecurityManager {

	public function init(): void {
		$this->disable_xmlrpc();
		$this->lockdown_rest_api();
		$this->restrict_application_passwords();
		$this->block_suspended_users();
		$this->block_sso_password_login();
		$this->block_sso_password_reset();
		$this->block_sso_email_change();
	}

	// ── XML-RPC ─────────────────────────────────────────────────────────────

	/**
	 * Completely disable XML-RPC to prevent brute-force amplification
	 * and pingback DDoS attacks.
	 */
	private function disable_xmlrpc(): void {
		// Disable the XML-RPC server.
		add_filter( 'xmlrpc_enabled', '__return_false' );

		// Remove the XML-RPC methods to be extra safe.
		add_filter( 'xmlrpc_methods', static fn( array $_methods ): array => array() );

		// Remove X-Pingback header.
		add_filter(
			'wp_headers',
			static function ( array $headers ): array {
				unset( $headers['X-Pingback'] );
				return $headers;
			}
		);

		// Remove the RSD link that advertises XML-RPC.
		remove_action( 'wp_head', 'rsd_link' );
	}

	// ── REST API User-Enumeration Lockdown ──────────────────────────────────

	/**
	 * Block unauthenticated access to /wp/v2/users to prevent user enumeration.
	 * Only allow users with the `list_users` capability.
	 */
	private function lockdown_rest_api(): void {
		add_filter(
			'rest_authentication_errors',
			static function ( ?\WP_Error $result ): ?\WP_Error {
				// Don't override an existing error.
				if ( is_wp_error( $result ) ) {
					return $result;
				}

				return $result;
			}
		);

		// Restrict the /wp/v2/users endpoint to users with `list_users`.
		add_filter(
			'rest_pre_dispatch',
			static function ( mixed $result, \WP_REST_Server $server, \WP_REST_Request $request ) {
				$route = $request->get_route();

				// Match /wp/v2/users and /wp/v2/users/<id>.
				if ( preg_match( '#^/wp/v2/users(?:/|$)#', $route ) ) {
					if ( ! current_user_can( 'list_users' ) ) {
						return new \WP_Error(
							'rest_forbidden',
							__( 'Access to the users endpoint is restricted.', 'enterprise-auth' ),
							array( 'status' => 403 )
						);
					}
				}

				return $result;
			},
			10,
			3
		);
	}

	// ── Application Passwords ───────────────────────────────────────────────

	/**
	 * Restrict Application Passwords to administrators only.
	 * Non-admins are denied the feature by default.
	 */
	private function restrict_application_passwords(): void {
		add_filter(
			'wp_is_application_passwords_available_for_user',
			static function ( bool $available, \WP_User $user ): bool {
				$settings              = SettingsController::read();
				$app_passwords_enabled = $settings['app_passwords'];

				if ( ! $app_passwords_enabled ) {
					// When globally disabled, only super-admins / administrators keep access.
					return user_can( $user, 'manage_options' );
				}

				return $available;
			},
			10,
			2
		);
	}

	// ── SCIM Suspension Login Block ─────────────────────────────────────────

	/**
	 * Block login for users suspended via SCIM deprovisioning.
	 *
	 * Hooks into the `authenticate` filter at a late priority so it runs
	 * after WordPress has resolved the user. If `is_scim_suspended` meta
	 * is strictly "true", the login is rejected regardless of method
	 * (password, Passkey, SSO).
	 */
	private function block_suspended_users(): void {
		add_filter(
			'authenticate',
			static function ( $user, string $username ) {
				// Only act when WordPress has already resolved a valid user.
				if ( ! ( $user instanceof \WP_User ) ) {
					return $user;
				}

				$suspended = get_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ), true );
				if ( 'true' === $suspended ) {
					return new \WP_Error(
						'account_suspended',
						__( 'Account suspended by Identity Provider.', 'enterprise-auth' )
					);
				}

				return $user;
			},
			100,
			2
		);
	}

	// ── SSO-Only Account Lockdown ───────────────────────────────────────────

	/**
	 * Check whether a user is SSO-bound (managed by an IdP or SCIM).
	 *
	 * User ID 1 (break-glass admin) is always excluded.
	 */
	private static function is_sso_bound( int $user_id ): bool {
		if ( 1 === $user_id ) {
			return false;
		}

		$idp_uid = get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::IDP_UID ), true );
		if ( '' !== $idp_uid ) {
			return true;
		}

		$scim_id = get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ), true );
		if ( '' !== $scim_id ) {
			return true;
		}

		return false;
	}

	/**
	 * Block local password login for SSO-bound users.
	 *
	 * Hooks at priority 20 (after wp_authenticate_username_password at 20)
	 * so the user object is resolved. Passkey and SSO logins bypass
	 * wp_authenticate entirely or go through separate flows.
	 */
	private function block_sso_password_login(): void {
		add_filter(
			'authenticate',
			static function ( $user, string $username, string $password ) {
				if ( ! ( $user instanceof \WP_User ) ) {
					return $user;
				}

				// Only block when a password was submitted (local login attempt).
				if ( '' === $password ) {
					return $user;
				}

				if ( self::is_sso_bound( $user->ID ) ) {
					return new \WP_Error(
						'sso_only_account',
						__( 'This account is managed by your organization. Please use Single Sign-On to log in.', 'enterprise-auth' )
					);
				}

				return $user;
			},
			25,
			3
		);
	}

	/**
	 * Block password reset (Lost Password) for SSO-bound users.
	 */
	private function block_sso_password_reset(): void {
		add_filter(
			'allow_password_reset',
			static function ( bool $allow, int $user_id ) {
				if ( self::is_sso_bound( $user_id ) ) {
					return false;
				}
				return $allow;
			},
			10,
			2
		);
	}

	// ── Email Change Protection ────────────────────────────────────────────

	/**
	 * Prevent SSO-managed users from changing their email address.
	 *
	 * Hooks into profile save validation and profile rendering to
	 * both enforce the restriction and communicate it in the UI.
	 */
	private function block_sso_email_change(): void {
		// Block email changes during profile save.
		add_action(
			'user_profile_update_errors',
			static function ( \WP_Error $errors, bool $update, \stdClass $user ) {
				if ( ! $update || empty( $user->ID ) ) {
					return;
				}

				if ( ! self::is_sso_bound( (int) $user->ID ) ) {
					return;
				}

				$existing = get_userdata( (int) $user->ID );
				if ( $existing && isset( $user->user_email ) && $user->user_email !== $existing->user_email ) {
					$errors->add(
						'sso_email_locked',
						__( 'Your email address is managed by your Identity Provider and cannot be changed locally.', 'enterprise-auth' )
					);
					// Restore the original email so WP core doesn't persist the change.
					$user->user_email = $existing->user_email;
				}
			},
			10,
			3
		);

		// Make the email field read-only in the profile UI.
		$render_readonly = static function ( \WP_User $user ): void {
			if ( ! self::is_sso_bound( $user->ID ) ) {
				return;
			}
			?>
			<script>
			( function() {
				var el = document.getElementById( 'email' );
				if ( el ) {
					el.setAttribute( 'readonly', 'readonly' );
					el.style.opacity = '0.7';
					var note = document.createElement( 'p' );
					note.className = 'description';
					note.textContent = 'This email address is managed by your Identity Provider.';
					el.parentNode.appendChild( note );
				}
			} )();
			</script>
			<?php
		};
		add_action( 'show_user_profile', $render_readonly );
		add_action( 'edit_user_profile', $render_readonly );
	}
}
