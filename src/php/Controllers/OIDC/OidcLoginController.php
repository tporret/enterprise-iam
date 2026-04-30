<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers\OIDC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\CurrentSiteIdpManager;
use EnterpriseAuth\Plugin\FederationFlowManager;
use EnterpriseAuth\Plugin\IdpManager;

/**
 * OIDC Authorization Redirect.
 *
 * Initiates the Authorization Code Flow by redirecting the user to the
 * configured OIDC Identity Provider.
 *
 * Route: GET /enterprise-auth/v1/oidc/login?idp_id={id}
 */
final class OidcLoginController {

	private const NAMESPACE = 'enterprise-auth/v1';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/oidc/login',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'login' ),
				'permission_callback' => '__return_true',
				'args'                => array(
					'idp_id' => array(
						'type'              => 'string',
						'required'          => true,
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);
	}

	/**
	 * Redirect the user to the OIDC IdP for authentication.
	 */
	public function login( \WP_REST_Request $request ): \WP_REST_Response {
		$idp_id = $request->get_param( 'idp_id' );
		$idp    = CurrentSiteIdpManager::find( (string) $idp_id );

		if ( ! $idp || ( $idp['protocol'] ?? '' ) !== 'oidc' ) {
			return new \WP_REST_Response( array( 'error' => 'OIDC IdP not found.' ), 404 );
		}

		if ( empty( $idp['enabled'] ) ) {
			return new \WP_REST_Response( array( 'error' => 'This IdP is currently disabled.' ), 403 );
		}

		$client_id     = $idp['client_id'] ?? '';
		$client_secret = $idp['client_secret'] ?? '';

		if ( empty( $client_id ) || empty( $client_secret ) ) {
			return new \WP_REST_Response( array( 'error' => 'OIDC client credentials not configured.' ), 500 );
		}

		try {
			// Set the redirect URI to our callback endpoint.
			$redirect_uri = rest_url( 'enterprise-auth/v1/oidc/callback' );

			// Use the authorization endpoint from our IdP config directly,
			// since getProviderConfigValue() is protected in the library.
			$auth_endpoint = $idp['authorization_endpoint'] ?? '';
			if ( empty( $auth_endpoint ) ) {
				return new \WP_REST_Response(
					array( 'error' => 'OIDC authorization endpoint not configured.' ),
					500
				);
			}

			$endpoint_validation = IdpManager::validate_runtime_endpoint_url( $auth_endpoint, 'authorization_endpoint' );
			if ( is_wp_error( $endpoint_validation ) ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Enterprise IAM – OIDC login error: ' . $endpoint_validation->get_error_message() );

				return new \WP_REST_Response(
					array( 'error' => 'Failed to initiate OIDC login. Please contact your administrator.' ),
					500
				);
			}

			$flow = FederationFlowManager::start_oidc_flow( (string) $idp_id, get_current_blog_id() );
			if ( is_wp_error( $flow ) ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Enterprise IAM – OIDC login error: ' . $flow->get_error_message() );

				return new \WP_REST_Response(
					array( 'error' => 'Failed to initiate OIDC login. Please contact your administrator.' ),
					500
				);
			}

			$auth_params = array(
				'response_type'         => 'code',
				'client_id'             => $client_id,
				'redirect_uri'          => $redirect_uri,
				'scope'                 => 'openid email profile',
				'state'                 => $flow['state'],
				'nonce'                 => $flow['nonce'],
				'code_challenge'        => $flow['code_challenge'],
				'code_challenge_method' => 'S256',
			);

			if ( ! empty( $idp['force_reauth'] ) ) {
				$auth_params['prompt'] = 'login';
			}

			$auth_url = add_query_arg( $auth_params, $auth_endpoint );

			return new \WP_REST_Response( null, 302, array( 'Location' => $auth_url ) );
		} catch ( \Throwable $e ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( 'Enterprise IAM – OIDC login error: ' . $e->getMessage() );
			return new \WP_REST_Response(
				array( 'error' => 'Failed to initiate OIDC login. Please contact your administrator.' ),
				500
			);
		}
	}

}
