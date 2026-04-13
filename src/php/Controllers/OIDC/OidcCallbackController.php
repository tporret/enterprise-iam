<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers\OIDC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\EnterpriseProvisioning;
use EnterpriseAuth\Plugin\CurrentSiteIdpManager;
use EnterpriseAuth\Plugin\FederationErrorHandler;
use EnterpriseAuth\Plugin\FederationFlowGuard;
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
	private const PUBLIC_ERROR_CODE = 'federation_failed';
	private string $last_error_reference = '';

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
		$log_context = array(
			'phase' => 'callback_entry',
		);

		// Handle IdP-side errors (e.g. user cancelled consent).
		if ( '' !== $error ) {
			if ( '' !== $state ) {
				$state_data = $this->consume_state( $state );
				if ( is_wp_error( $state_data ) ) {
					$this->log_detailed_error(
						$state_data->get_error_message(),
						array( 'phase' => 'provider_error_state_validation' )
					);
					return $this->error_redirect();
				}

				$log_context['idp_id'] = (string) ( $state_data['idp_id'] ?? '' );
			}

			$desc = $this->get_callback_param( $request, 'error_description' );

			$message = 'OIDC provider error ' . sanitize_text_field( $error );
			if ( '' !== $desc ) {
				$message .= ': ' . sanitize_text_field( $desc );
			}

			$log_context['phase'] = 'provider_error';
			$this->log_detailed_error( $message, $log_context );
			return $this->error_redirect();
		}

		if ( empty( $code ) || empty( $state ) ) {
			$this->log_detailed_error( 'Missing authorization code or state.', array( 'phase' => 'parameter_validation' ) );
			return $this->error_redirect();
		}

		// ── Validate state (CSRF protection) ────────────────────────────
		$state_data = $this->consume_state( $state );
		if ( is_wp_error( $state_data ) ) {
			$this->log_detailed_error( $state_data->get_error_message(), array( 'phase' => 'state_validation' ) );
			return $this->error_redirect();
		}

		$idp_id = $state_data['idp_id'] ?? '';
		$nonce  = $state_data['nonce'] ?? '';
		$code_verifier = $state_data['code_verifier'] ?? '';
		$blog_id = (int) ( $state_data['blog_id'] ?? get_current_blog_id() );
		$idp    = CurrentSiteIdpManager::find_for_blog( $blog_id, (string) $idp_id );
		$log_context = array(
			'idp_id' => (string) $idp_id,
		);

		if ( ! $idp || ( $idp['protocol'] ?? '' ) !== 'oidc' || '' === $nonce || '' === $code_verifier ) {
			$this->log_detailed_error(
				'OIDC callback could not resolve a valid IdP or PKCE state.',
				$log_context + array( 'phase' => 'idp_resolution' )
			);
			return $this->error_redirect();
		}

		// ── Token exchange via OpenIDConnectClient ──────────────────────
		try {
			$runtime_validation = IdpManager::validate_runtime_oidc_configuration( $idp );
			if ( is_wp_error( $runtime_validation ) ) {
				$this->log_detailed_error(
					$runtime_validation->get_error_message(),
					$log_context + array( 'phase' => 'runtime_validation' )
				);
				return $this->error_redirect();
			}

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
			$id_token = $oidc->getIdToken();
			$id_token = is_string( $id_token ) ? $id_token : '';

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
				$this->log_detailed_error(
					'No valid email address was present in OIDC claims.',
					$log_context + array( 'phase' => 'claim_validation' )
				);
				return $this->error_redirect();
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
				$this->log_detailed_error(
					'OIDC issuer mismatch: token issuer did not match the configured IdP.',
					$log_context + array( 'phase' => 'issuer_validation' )
				);
				return $this->error_redirect();
			}

			$attributes = array(
				'email'          => sanitize_email( $email ),
				'first_name'     => sanitize_text_field( (string) $given_name ),
				'last_name'      => sanitize_text_field( (string) $family_name ),
				'groups'         => array_map( 'sanitize_text_field', $groups ),
				'idp_uid'        => sanitize_text_field( $sub ),
				'idp_issuer'     => esc_url_raw( $iss ),
				'oidc_id_token'  => $id_token,
				'email_verified' => ( true === $email_verified || 'true' === $email_verified ),
			);

			// ── JIT provisioning and login ──────────────────────────────
			$result = EnterpriseProvisioning::provision_and_login( $idp, $attributes );

			if ( is_wp_error( $result ) ) {
				$this->log_detailed_error(
					$result->get_error_message(),
					$log_context + array( 'phase' => 'provisioning' )
				);
				return $this->error_redirect();
			}

			return $this->success_redirect();
		} catch ( \Throwable $e ) {
			$this->log_detailed_error(
				'Unhandled exception during OIDC callback processing.',
				$log_context + array( 'phase' => 'callback_exception' ),
				$e
			);
			return $this->error_redirect();
		}
	}

	/**
	 * Redirect to wp-login.php with a generic SSO error code.
	 */
	private function error_redirect(): \WP_REST_Response {
		$url = FederationErrorHandler::login_error_url( self::PUBLIC_ERROR_CODE, $this->last_error_reference );

		return new \WP_REST_Response( null, 302, array( 'Location' => $url ) );
	}

	/**
	 * Log the detailed protocol error for administrator troubleshooting.
	 */
	private function log_detailed_error( string $detail, array $context = array(), ?\Throwable $exception = null ): void {
		$this->last_error_reference = FederationErrorHandler::log(
			'oidc',
			'oidc_callback',
			$detail,
			$context,
			$exception
		);
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
	 * @return array<string, mixed>|\WP_Error
	 */
	private function consume_state( string $state ) {
		$state_data = FederationFlowGuard::consume( 'oidc', $state );
		if ( is_wp_error( $state_data ) ) {
			return $state_data;
		}

		if ( isset( $state_data['state'] ) && (string) $state_data['state'] !== $state ) {
			return new \WP_Error( 'ea_oidc_state_mismatch', 'OIDC state did not match the stored federation flow.' );
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

}
