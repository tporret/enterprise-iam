<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers\OIDC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\IdpManager;
use Jumbojett\OpenIDConnectClient;

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
		register_rest_route( self::NAMESPACE, '/oidc/login', [
			'methods'             => \WP_REST_Server::READABLE,
			'callback'            => [ $this, 'login' ],
			'permission_callback' => '__return_true',
			'args'                => [
				'idp_id' => [
					'type'              => 'string',
					'required'          => true,
					'sanitize_callback' => 'sanitize_text_field',
				],
			],
		] );
	}

	/**
	 * Redirect the user to the OIDC IdP for authentication.
	 */
	public function login( \WP_REST_Request $request ): \WP_REST_Response {
		$idp_id = $request->get_param( 'idp_id' );
		$idp    = IdpManager::find( $idp_id );

		if ( ! $idp || ( $idp['protocol'] ?? '' ) !== 'oidc' ) {
			return new \WP_REST_Response( [ 'error' => 'OIDC IdP not found.' ], 404 );
		}

		if ( empty( $idp['enabled'] ) ) {
			return new \WP_REST_Response( [ 'error' => 'This IdP is currently disabled.' ], 403 );
		}

		$issuer        = $idp['issuer'] ?? ( $idp['authorization_endpoint'] ?? '' );
		$client_id     = $idp['client_id'] ?? '';
		$client_secret = $idp['client_secret'] ?? '';

		if ( empty( $client_id ) || empty( $client_secret ) ) {
			return new \WP_REST_Response( [ 'error' => 'OIDC client credentials not configured.' ], 500 );
		}

		try {
			$oidc = new OpenIDConnectClient( $issuer, $client_id, $client_secret );

			// Set the redirect URI to our callback endpoint.
			$redirect_uri = rest_url( 'enterprise-auth/v1/oidc/callback' );
			$oidc->setRedirectURL( $redirect_uri );

			// Request standard scopes.
			$oidc->addScope( [ 'openid', 'email', 'profile' ] );

			// Generate cryptographic state and nonce for CSRF / replay protection.
			$state = bin2hex( random_bytes( 16 ) );
			$nonce = bin2hex( random_bytes( 16 ) );

			// Store state + nonce + IdP ID in a WP Transient (5-minute TTL).
			set_transient( 'ea_oidc_state_' . $state, wp_json_encode( [
				'idp_id' => $idp_id,
				'nonce'  => $nonce,
			] ), 300 );

			// Write state/nonce to PHP session so the library's protected
			// getState()/getNonce() can read them on the callback request.
			if ( session_status() === PHP_SESSION_NONE ) {
				@session_start();
			}
			$_SESSION['openid_connect_state'] = $state;
			$_SESSION['openid_connect_nonce'] = $nonce;
			session_write_close();

			// If the IdP has explicit endpoint overrides, configure them
			// so the library skips discovery.
			if ( ! empty( $idp['authorization_endpoint'] ) ) {
				$oidc->providerConfigParam( [
					'authorization_endpoint' => $idp['authorization_endpoint'],
					'token_endpoint'         => $idp['token_endpoint'] ?? '',
					'userinfo_endpoint'      => $idp['userinfo_endpoint'] ?? '',
					'jwks_uri'               => $idp['jwks_uri'] ?? '',
				] );
			}

			// Use the authorization endpoint from our IdP config directly,
			// since getProviderConfigValue() is protected in the library.
			$auth_endpoint = $idp['authorization_endpoint'] ?? '';
			if ( empty( $auth_endpoint ) ) {
				return new \WP_REST_Response(
					[ 'error' => 'OIDC authorization endpoint not configured.' ],
					500
				);
			}

			$auth_url = add_query_arg( [
				'response_type' => 'code',
				'client_id'     => $client_id,
				'redirect_uri'  => $redirect_uri,
				'scope'         => 'openid email profile',
				'state'         => $state,
				'nonce'         => $nonce,
			], $auth_endpoint );

			return new \WP_REST_Response( null, 302, [ 'Location' => $auth_url ] );
		} catch ( \Throwable $e ) {
			return new \WP_REST_Response(
				[ 'error' => 'Failed to initiate OIDC login: ' . $e->getMessage() ],
				500
			);
		}
	}
}
