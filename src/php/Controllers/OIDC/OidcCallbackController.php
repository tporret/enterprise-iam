<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers\OIDC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\EnterpriseProvisioning;
use EnterpriseAuth\Plugin\IdpManager;
use EnterpriseAuth\Plugin\OidcTransientClient;

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
				'args'                => array(
					'code'              => array(
						'type'              => 'string',
						'required'          => false,
						'sanitize_callback' => 'sanitize_text_field',
					),
					'state'             => array(
						'type'              => 'string',
						'required'          => false,
						'sanitize_callback' => 'sanitize_text_field',
					),
					'error'             => array(
						'type'              => 'string',
						'required'          => false,
						'sanitize_callback' => 'sanitize_text_field',
					),
					'error_description' => array(
						'type'              => 'string',
						'required'          => false,
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);
	}

	/**
	 * Handle the OIDC authorization code callback.
	 */
	public function callback( \WP_REST_Request $request ): \WP_REST_Response {
		$code  = $this->get_callback_param( $request, 'code' );
		$state = $this->get_callback_param( $request, 'state' );
		$error = $this->get_callback_param( $request, 'error' );

		// Handle IdP-side errors (e.g. user cancelled consent).
		if ( '' !== $error ) {
			if ( '' !== $state ) {
				$state_data = $this->consume_state( $state );
				if ( null === $state_data ) {
					return $this->error_redirect( 'Invalid or expired OIDC state. Please try again.' );
				}
			}

			$desc = $this->get_callback_param( $request, 'error_description' );

			$message = 'OIDC provider error ' . sanitize_text_field( $error );
			if ( '' !== $desc ) {
				$message .= ': ' . sanitize_text_field( $desc );
			}

			return $this->error_redirect( $message );
		}

		if ( empty( $code ) || empty( $state ) ) {
			return $this->error_redirect( 'Missing authorization code or state.' );
		}

		// ── Validate state (CSRF protection) ────────────────────────────
		$state_data = $this->consume_state( $state );
		if ( null === $state_data ) {
			return $this->error_redirect( 'Invalid or expired OIDC state. Please try again.' );
		}

		$idp_id = $state_data['idp_id'] ?? '';
		$nonce  = $state_data['nonce'] ?? '';
		$code_verifier = $state_data['code_verifier'] ?? '';
		$idp    = IdpManager::find( $idp_id );

		if ( ! $idp || ( $idp['protocol'] ?? '' ) !== 'oidc' || '' === $nonce || '' === $code_verifier ) {
			return $this->error_redirect( 'OIDC Identity Provider not found.' );
		}

		// ── Token exchange via OpenIDConnectClient ──────────────────────
		try {
			$issuer        = $idp['issuer'] ?? ( $idp['authorization_endpoint'] ?? '' );
			$client_id     = $idp['client_id'] ?? '';
			$client_secret = $idp['client_secret'] ?? '';

			$oidc = new OidcTransientClient( $issuer, $client_id, $client_secret );
			$oidc->prime_session_store(
				array(
					'openid_connect_state'         => $state,
					'openid_connect_nonce'         => $nonce,
					'openid_connect_code_verifier' => $code_verifier,
				)
			);

			$redirect_uri = rest_url( 'enterprise-auth/v1/oidc/callback' );
			$oidc->setRedirectURL( $redirect_uri );

			// Enable PKCE so the library sends the transient-backed
			// code_verifier during the token exchange (RFC 7636).
			$oidc->setCodeChallengeMethod( 'S256' );

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

			// Authenticate performs the token exchange and JWT verification
			// (signature via JWKS, audience, expiry, nonce).
			$oidc->authenticate();

			// ── Extract user claims ─────────────────────────────────────
			$use_custom = ! empty( $idp['override_attribute_mapping'] );

			$email_key      = ( $use_custom && ! empty( $idp['custom_email_attr'] ) ) ? $idp['custom_email_attr'] : 'email';
			$first_name_key = ( $use_custom && ! empty( $idp['custom_first_name_attr'] ) ) ? $idp['custom_first_name_attr'] : 'given_name';
			$last_name_key  = ( $use_custom && ! empty( $idp['custom_last_name_attr'] ) ) ? $idp['custom_last_name_attr'] : 'family_name';

			$email       = $oidc->getVerifiedClaims( $email_key );
			$given_name  = $oidc->getVerifiedClaims( $first_name_key );
			$family_name = $oidc->getVerifiedClaims( $last_name_key );
			$given_name  = is_string( $given_name ) ? $given_name : '';
			$family_name = is_string( $family_name ) ? $family_name : '';
			$groups      = $oidc->getVerifiedClaims( 'groups' );

			// Fallback: try requestUserInfo if email not in ID token.
			if ( empty( $email ) ) {
				$userinfo = $oidc->requestUserInfo();
				$email    = $userinfo->{$email_key} ?? '';
				if ( '' === $given_name ) {
					$given_name = (string) ( $userinfo->{$first_name_key} ?? '' );
				}
				if ( '' === $family_name ) {
					$family_name = (string) ( $userinfo->{$last_name_key} ?? '' );
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

			// Extract the immutable subject identifier for strict account binding.
			$sub = $oidc->getVerifiedClaims( 'sub' );
			$sub = is_string( $sub ) ? $sub : '';

			// Extract the canonical issuer identifier (iss claim).
			$iss = $oidc->getVerifiedClaims( 'iss' );
			$iss = is_string( $iss ) ? $iss : ( is_string( $issuer ) ? $issuer : '' );

			// Check whether the IdP has verified the user's email address.
			$email_verified = $oidc->getVerifiedClaims( 'email_verified' );

			// ── Explicit issuer validation (defense-in-depth) ───────
			$configured_issuer = rtrim( (string) $issuer, '/' );
			$token_issuer      = rtrim( (string) $iss, '/' );
			if ( '' !== $configured_issuer && '' !== $token_issuer && $configured_issuer !== $token_issuer ) {
				return $this->error_redirect( 'OIDC issuer mismatch: token issuer does not match configured IdP.' );
			}

			$attributes = array(
				'email'          => sanitize_email( $email ),
				'first_name'     => sanitize_text_field( (string) $given_name ),
				'last_name'      => sanitize_text_field( (string) $family_name ),
				'groups'         => array_map( 'sanitize_text_field', $groups ),
				'idp_uid'        => sanitize_text_field( $sub ),
				'idp_issuer'     => esc_url_raw( $iss ),
				'email_verified' => ( true === $email_verified || 'true' === $email_verified ),
			);

			// ── JIT provisioning and login ──────────────────────────────
			$result = EnterpriseProvisioning::provision_and_login( $idp, $attributes );

			if ( is_wp_error( $result ) ) {
				return $this->error_redirect( $result->get_error_message() );
			}

			return $this->success_redirect();
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Enterprise IAM – OIDC callback error: ' . $e->getMessage() );
			}
			return $this->error_redirect( 'OIDC authentication failed. Please try again or contact your administrator.' );
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

	/**
	 * Validate and consume OIDC state transient (one-time use).
	 *
	 * @return array<string, mixed>|null
	 */
	private function consume_state( string $state ): ?array {
		if ( '' === $state ) {
			return null;
		}

		$transient_key = self::verification_transient_key( $state );
		$state_raw     = get_transient( $transient_key );
		delete_transient( $transient_key );

		if ( ! $state_raw ) {
			return null;
		}

		$state_data = json_decode( (string) $state_raw, true );
		if ( ! is_array( $state_data ) ) {
			return null;
		}

		if ( isset( $state_data['blog_id'] ) && (int) $state_data['blog_id'] !== get_current_blog_id() ) {
			return null;
		}

		if ( isset( $state_data['state'] ) && (string) $state_data['state'] !== $state ) {
			return null;
		}

		return $state_data;
	}

	/**
	 * Resolve callback parameters from REST params first, then raw query string.
	 */
	private function get_callback_param( \WP_REST_Request $request, string $key ): string {
		$value = (string) $request->get_param( $key );
		if ( '' !== $value ) {
			return $value;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$query_string = $_SERVER['QUERY_STRING'] ?? '';
		if ( '' === $query_string ) {
			return '';
		}

		$parsed_query = array();
		parse_str( $query_string, $parsed_query );
		if ( empty( $parsed_query[ $key ] ) ) {
			return '';
		}

		return sanitize_text_field( (string) $parsed_query[ $key ] );
	}

	/**
	 * Blog-scoped transient key for OIDC verification state.
	 */
	private static function verification_transient_key( string $state ): string {
		return 'ea_oidc_v_' . get_current_blog_id() . '_' . sanitize_text_field( $state );
	}
}
