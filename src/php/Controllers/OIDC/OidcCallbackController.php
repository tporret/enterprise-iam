<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers\OIDC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\EnterpriseProvisioning;
use EnterpriseAuth\Plugin\IdpManager;
use Jumbojett\OpenIDConnectClient;

/**
 * OIDC Authorization Code Callback.
 *
 * Receives the authorization code from the IdP, exchanges it for an
 * ID Token (with JWT/JWKS verification via the library), extracts user
 * claims, and invokes JIT provisioning.
 *
 * Route: GET /enterprise-auth/v1/oidc/callback
 */
final class OidcCallbackController {

	private const NAMESPACE = 'enterprise-auth/v1';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/oidc/callback',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'callback' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Handle the OIDC authorization code callback.
	 */
	public function callback( \WP_REST_Request $request ): \WP_REST_Response {
		$code  = $request->get_param( 'code' );
		$state = $request->get_param( 'state' );
		$error = $request->get_param( 'error' );

		// Handle IdP-side errors (e.g. user cancelled consent).
		if ( $error ) {
			$desc = $request->get_param( 'error_description' );
			if ( empty( $desc ) ) {
				$desc = $error;
			}
			return $this->error_redirect( 'IdP error: ' . sanitize_text_field( $desc ) );
		}

		if ( empty( $code ) || empty( $state ) ) {
			return $this->error_redirect( 'Missing authorization code or state.' );
		}

		// ── Validate state (CSRF protection) ────────────────────────────
		$transient_key = 'ea_oidc_state_' . sanitize_text_field( $state );
		$state_raw     = get_transient( $transient_key );
		delete_transient( $transient_key ); // one-time use

		if ( ! $state_raw ) {
			return $this->error_redirect( 'Invalid or expired OIDC state. Please try again.' );
		}

		$state_data = json_decode( $state_raw, true );
		$idp_id     = $state_data['idp_id'] ?? '';
		$nonce      = $state_data['nonce'] ?? '';
		$idp        = IdpManager::find( $idp_id );

		if ( ! $idp || ( $idp['protocol'] ?? '' ) !== 'oidc' ) {
			return $this->error_redirect( 'OIDC Identity Provider not found.' );
		}

		// ── Token exchange via OpenIDConnectClient ──────────────────────
		try {
			$issuer        = $idp['issuer'] ?? ( $idp['authorization_endpoint'] ?? '' );
			$client_id     = $idp['client_id'] ?? '';
			$client_secret = $idp['client_secret'] ?? '';

			$oidc = new OpenIDConnectClient( $issuer, $client_id, $client_secret );

			$redirect_uri = rest_url( 'enterprise-auth/v1/oidc/callback' );
			$oidc->setRedirectURL( $redirect_uri );

			// Configure explicit provider endpoints if available so the
			// library doesn't need to perform discovery.
			if ( ! empty( $idp['authorization_endpoint'] ) ) {
				$oidc->providerConfigParam(
					array(
						'authorization_endpoint' => $idp['authorization_endpoint'],
						'token_endpoint'         => $idp['token_endpoint'] ?? '',
						'userinfo_endpoint'      => $idp['userinfo_endpoint'] ?? '',
						'jwks_uri'               => $idp['jwks_uri'] ?? '',
					)
				);
			}

			// Inject code and state into the superglobals the library reads.
			$_REQUEST['code']  = $code;
			$_REQUEST['state'] = $state;

			// The library reads state/nonce from $_SESSION (set by
			// OidcLoginController). The PHP session cookie carries them
			// across the browser redirect from the IdP.

			// Authenticate performs the token exchange and JWT verification
			// (signature via JWKS, audience, expiry, nonce).
			$oidc->authenticate();

			// ── Extract user claims ─────────────────────────────────────
			$email       = $oidc->getVerifiedClaims( 'email' );
			$given_name  = $oidc->getVerifiedClaims( 'given_name' );
			$family_name = $oidc->getVerifiedClaims( 'family_name' );
			$given_name  = is_string( $given_name ) ? $given_name : '';
			$family_name = is_string( $family_name ) ? $family_name : '';
			$groups      = $oidc->getVerifiedClaims( 'groups' );

			// Fallback: try requestUserInfo if email not in ID token.
			if ( empty( $email ) ) {
				$userinfo = $oidc->requestUserInfo();
				$email    = $userinfo->email ?? '';
				if ( '' === $given_name ) {
					$given_name = (string) ( $userinfo->given_name ?? '' );
				}
				if ( '' === $family_name ) {
					$family_name = (string) ( $userinfo->family_name ?? '' );
				}
				if ( empty( $groups ) ) {
					$groups = $userinfo->groups ?? array();
				}
			}

			if ( empty( $email ) || ! is_email( $email ) ) {
				return $this->error_redirect( 'No valid email address in OIDC claims.' );
			}

			// Normalize groups to array.
			if ( ! is_array( $groups ) ) {
				$groups = $groups ? array( $groups ) : array();
			}

			$attributes = array(
				'email'      => sanitize_email( $email ),
				'first_name' => sanitize_text_field( (string) $given_name ),
				'last_name'  => sanitize_text_field( (string) $family_name ),
				'groups'     => array_map( 'sanitize_text_field', $groups ),
			);

			// ── JIT provisioning and login ──────────────────────────────
			$result = EnterpriseProvisioning::provision_and_login( $idp, $attributes );

			if ( is_wp_error( $result ) ) {
				return $this->error_redirect( $result->get_error_message() );
			}

			return $this->success_redirect();
		} catch ( \Throwable $e ) {
			return $this->error_redirect( 'OIDC authentication failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Redirect to wp-login.php with an error message.
	 */
	private function error_redirect( string $message ): \WP_REST_Response {
		$url = add_query_arg(
			array(
				'ea_sso_error' => rawurlencode( $message ),
			),
			wp_login_url()
		);

		return new \WP_REST_Response( null, 302, array( 'Location' => $url ) );
	}

	/**
	 * Redirect to the admin dashboard on successful login.
	 */
	private function success_redirect(): \WP_REST_Response {
		return new \WP_REST_Response( null, 302, array( 'Location' => admin_url() ) );
	}
}
