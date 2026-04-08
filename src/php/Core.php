<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\Controllers\IdpController;
use EnterpriseAuth\Plugin\Controllers\LoginRouter;
use EnterpriseAuth\Plugin\Controllers\ScimController;
use EnterpriseAuth\Plugin\Controllers\OIDC\OidcCallbackController;
use EnterpriseAuth\Plugin\Controllers\OIDC\OidcLoginController;
use EnterpriseAuth\Plugin\Controllers\PasskeyLoginController;
use EnterpriseAuth\Plugin\Controllers\PasskeyRegistrationController;
use EnterpriseAuth\Plugin\Controllers\SAML\SamlAcsController;
use EnterpriseAuth\Plugin\Controllers\SAML\SamlLoginController;
use EnterpriseAuth\Plugin\Controllers\SAML\SamlMetadataController;

/**
 * Core bootstrap class.
 *
 * Wires all plugin sub-systems together.
 */
final class Core {

	public function init(): void {
		// Security hardening – runs on every request.
		( new SecurityManager() )->init();

		// Admin UI – only in wp-admin context.
		if ( is_admin() ) {
			( new AdminUI() )->init();
		}

		// REST API controllers.
		add_action(
			'rest_api_init',
			static function (): void {
				( new SettingsController() )->register_routes();
				( new PasskeyRegistrationController() )->register_routes();
				( new PasskeyLoginController() )->register_routes();
				( new IdpController() )->register_routes();
				( new LoginRouter() )->register_routes();
				( new SamlMetadataController() )->register_routes();
				( new SamlLoginController() )->register_routes();
				( new SamlAcsController() )->register_routes();
				( new OidcLoginController() )->register_routes();
				( new OidcCallbackController() )->register_routes();
				( new ScimController() )->register_routes();
			}
		);

		// Passkey login injection on wp-login.php.
		( new LoginFlow() )->init();

		// SSO session control — cap auth-cookie lifetime for SSO users
		// and enforce SAML SessionNotOnOrAfter.
		add_filter( 'auth_cookie_expiration', array( $this, 'cap_sso_session_lifetime' ), 10, 3 );
		add_action( 'init', array( $this, 'enforce_sso_session_expiry' ) );

		// Seamless SSO re-auth — intercept wp-login.php and redirect
		// SSO users back to their IdP instead of showing the local form.
		add_action( 'login_init', array( $this, 'intercept_login_for_sso_reauth' ) );

		// Security headers on frontend.
		add_action( 'send_headers', array( $this, 'send_security_headers' ) );
	}

	/**
	 * Append strict security headers when they are not already present.
	 */
	public function send_security_headers(): void {
		$headers = array(
			'X-Frame-Options'        => 'SAMEORIGIN',
			'X-Content-Type-Options' => 'nosniff',
			'Referrer-Policy'        => 'strict-origin-when-cross-origin',
			'Permissions-Policy'     => 'geolocation=(), camera=(), microphone=()',
		);

		foreach ( $headers as $name => $value ) {
			if ( ! headers_sent() ) {
				header( sprintf( '%s: %s', $name, $value ), false );
			}
		}
	}

	/**
	 * Cap auth-cookie expiration for SSO-provisioned users.
	 *
	 * WordPress defaults to 48 hours (logged-in) or 14 days (remember-me).
	 * For SSO users we cap it at the admin-configured session timeout
	 * (default 8 hours) to limit exposure from stolen cookies.
	 *
	 * @param int  $length  Expiration length in seconds.
	 * @param int  $user_id User ID.
	 * @param bool $remember Whether "remember me" is checked.
	 * @return int
	 */
	public function cap_sso_session_lifetime( int $length, int $user_id, bool $remember ): int {
		$sso_provider = get_user_meta( $user_id, '_enterprise_auth_sso_provider', true );
		if ( empty( $sso_provider ) ) {
			// Local account — don't interfere with default WP behaviour.
			return $length;
		}

		$settings       = SettingsController::read();
		$timeout_hours  = $settings['session_timeout'] ?? 8;
		$timeout_seconds = $timeout_hours * HOUR_IN_SECONDS;

		return min( $length, $timeout_seconds );
	}

	/**
	 * Force logout SSO users whose session has exceeded the configured
	 * timeout or the SAML SessionNotOnOrAfter deadline.
	 *
	 * Runs on every `init` hook for logged-in users. The meta lookups are
	 * single-key reads (auto-loaded), so the overhead is negligible.
	 */
	public function enforce_sso_session_expiry(): void {
		if ( ! is_user_logged_in() ) {
			return;
		}

		$user_id     = get_current_user_id();
		$sso_provider = get_user_meta( $user_id, '_enterprise_auth_sso_provider', true );
		if ( empty( $sso_provider ) ) {
			return; // Local account.
		}

		$now      = time();
		$login_at = (int) get_user_meta( $user_id, '_enterprise_auth_sso_login_at', true );

		// Check admin-configured session timeout.
		if ( $login_at > 0 ) {
			$settings        = SettingsController::read();
			$timeout_seconds = ( $settings['session_timeout'] ?? 8 ) * HOUR_IN_SECONDS;

			if ( ( $now - $login_at ) > $timeout_seconds ) {
				$this->force_sso_logout( $user_id );
				return;
			}
		}

		// Check IdP-mandated session expiry (SAML SessionNotOnOrAfter).
		$session_expires = (int) get_user_meta( $user_id, '_enterprise_auth_session_expires', true );
		if ( $session_expires > 0 && $now >= $session_expires ) {
			$this->force_sso_logout( $user_id );
			return;
		}
	}

	/**
	 * Destroy the WordPress session and redirect to the IdP for re-auth.
	 *
	 * If the user's last-used IdP is known (via cookie or usermeta),
	 * redirect directly to the SSO login endpoint for seamless re-auth.
	 * Otherwise fall back to wp-login.php.
	 */
	private function force_sso_logout( int $user_id ): void {
		// Read the SSO provider binding BEFORE destroying the session.
		$sso_provider = get_user_meta( $user_id, '_enterprise_auth_sso_provider', true );
		$idp          = ! empty( $sso_provider ) ? IdpManager::find( $sso_provider ) : null;

		// Clean up SSO session meta.
		delete_user_meta( $user_id, '_enterprise_auth_sso_login_at' );
		delete_user_meta( $user_id, '_enterprise_auth_session_expires' );

		wp_logout();

		// If the IdP is still valid and enabled, redirect directly for re-auth.
		if ( $idp && ! empty( $idp['enabled'] ) ) {
			$protocol = $idp['protocol'] ?? '';
			if ( 'saml' === $protocol ) {
				$redirect = rest_url( 'enterprise-auth/v1/saml/login?idp_id=' . rawurlencode( $idp['id'] ) );
			} elseif ( 'oidc' === $protocol ) {
				$redirect = rest_url( 'enterprise-auth/v1/oidc/login?idp_id=' . rawurlencode( $idp['id'] ) );
			} else {
				$redirect = add_query_arg(
					'ea_sso_error',
					rawurlencode( 'Your SSO session has expired. Please log in again.' ),
					wp_login_url()
				);
			}
		} else {
			$redirect = add_query_arg(
				'ea_sso_error',
				rawurlencode( 'Your SSO session has expired. Please log in again.' ),
				wp_login_url()
			);
		}

		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Intercept wp-login.php and automatically redirect SSO users back
	 * to their IdP for seamless re-authentication.
	 *
	 * Only fires when:
	 * - The user has a `enterprise_auth_last_idp` cookie
	 * - The login action is the default (not logout, register, etc.)
	 * - The request has reauth=1 or redirect_to (expired session bounce)
	 */
	public function intercept_login_for_sso_reauth(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = sanitize_text_field( $_REQUEST['action'] ?? 'login' );

		// Only intercept the default login action.
		if ( 'login' !== $action && '' !== $action ) {
			return;
		}

		// Don't intercept explicit ea_sso_error displays or logout actions.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET['ea_sso_error'] ) || ! empty( $_GET['loggedout'] ) ) {
			return;
		}

		// Check for the last-used IdP cookie.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$last_idp_id = isset( $_COOKIE['enterprise_auth_last_idp'] )
			? sanitize_text_field( wp_unslash( $_COOKIE['enterprise_auth_last_idp'] ) )
			: '';

		if ( '' === $last_idp_id ) {
			return;
		}

		// Only redirect when the session has expired (reauth or redirect_to present).
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$is_reauth = ! empty( $_GET['reauth'] ) || ! empty( $_GET['redirect_to'] );
		if ( ! $is_reauth ) {
			return;
		}

		$idp = IdpManager::find( $last_idp_id );
		if ( ! $idp || empty( $idp['enabled'] ) ) {
			return;
		}

		$protocol = $idp['protocol'] ?? '';
		if ( 'saml' === $protocol ) {
			$redirect = rest_url( 'enterprise-auth/v1/saml/login?idp_id=' . rawurlencode( $idp['id'] ) );
		} elseif ( 'oidc' === $protocol ) {
			$redirect = rest_url( 'enterprise-auth/v1/oidc/login?idp_id=' . rawurlencode( $idp['id'] ) );
		} else {
			return;
		}

		wp_safe_redirect( $redirect );
		exit;
	}
}
