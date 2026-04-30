<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\CurrentSiteIdpManager;
use EnterpriseAuth\Plugin\FederationFlowManager;
use EnterpriseAuth\Plugin\SamlSettingsFactory;

/**
 * SP-Initiated SAML Login.
 *
 * Generates an AuthnRequest and redirects the user to the configured IdP.
 *
 * Route: GET /enterprise-auth/v1/saml/login?idp_id={id}
 */
final class SamlLoginController {

	private const NAMESPACE = 'enterprise-auth/v1';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/saml/login',
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
	 * Build the SAML AuthnRequest and redirect to the IdP SSO URL.
	 */
	public function login( \WP_REST_Request $request ): \WP_REST_Response {
		$idp_id = $request->get_param( 'idp_id' );
		$idp    = CurrentSiteIdpManager::find( (string) $idp_id );

		if ( ! $idp || ( $idp['protocol'] ?? '' ) !== 'saml' ) {
			return new \WP_REST_Response( array( 'error' => 'SAML IdP not found.' ), 404 );
		}

		if ( empty( $idp['enabled'] ) ) {
			return new \WP_REST_Response( array( 'error' => 'This IdP is currently disabled.' ), 403 );
		}

		try {
			$settings = SamlSettingsFactory::build( $idp );
			$auth     = new \OneLogin\Saml2\Auth( $settings );

			$flow = FederationFlowManager::start_saml_flow(
				(string) $idp_id,
				get_current_blog_id(),
				static function ( string $relay_state ) use ( $auth, $idp ) {
					// The OneLogin library's login() uses $returnTo as the
					// RelayState value. We pass a per-request flow key so the ACS
					// controller can resolve the expected IdP and request binding.
					$sso_url = $auth->login(
						$relay_state,
						array(),                               // parameters
						! empty( $idp['force_reauth'] ),       // forceAuthn
						false,                                 // isPassive
						true                                   // stay — return the redirect URL
					);

					if ( empty( $sso_url ) ) {
						return new \WP_Error(
							'ea_federation_flow_saml_url',
							'Could not build SAML AuthnRequest URL.'
						);
					}

					$request_id = $auth->getLastRequestID();
					if ( empty( $request_id ) ) {
						return new \WP_Error(
							'ea_federation_flow_saml_request_id',
							'Could not correlate the SAML authentication request.'
						);
					}

					return array(
						'redirect_url' => (string) $sso_url,
						'request_id'   => (string) $request_id,
					);
				}
			);

			if ( is_wp_error( $flow ) ) {
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
					error_log( 'Enterprise IAM – SAML login error: ' . $flow->get_error_message() );
				}

				return new \WP_REST_Response(
					array( 'error' => 'Failed to initiate SAML login. Please contact your administrator.' ),
					500
				);
			}

			return new \WP_REST_Response( null, 302, array( 'Location' => $flow['redirect_url'] ) );
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Enterprise IAM – SAML login error: ' . $e->getMessage() );
			}
			return new \WP_REST_Response(
				array( 'error' => 'Failed to initiate SAML login. Please contact your administrator.' ),
				500
			);
		}
	}

}
