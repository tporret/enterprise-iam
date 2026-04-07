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
}
