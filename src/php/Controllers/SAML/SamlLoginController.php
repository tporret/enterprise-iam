<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\IdpManager;
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
		$idp    = IdpManager::find( $idp_id );

		if ( ! $idp || ( $idp['protocol'] ?? '' ) !== 'saml' ) {
			return new \WP_REST_Response( array( 'error' => 'SAML IdP not found.' ), 404 );
		}

		if ( empty( $idp['enabled'] ) ) {
			return new \WP_REST_Response( array( 'error' => 'This IdP is currently disabled.' ), 403 );
		}

		try {
			$settings = SamlSettingsFactory::build( $idp );
			$auth     = new \OneLogin\Saml2\Auth( $settings );

			// The OneLogin library's login() uses $returnTo as the
			// RelayState value. We pass the IdP ID so the ACS
			// controller can look up the config after the IdP responds.
			$sso_url = $auth->login(
				$idp_id,                              // returnTo — becomes RelayState (IdP ID)
				array(),                               // parameters
				! empty( $idp['force_reauth'] ),       // forceAuthn
				false,                                 // isPassive
				true                                   // stay — return the redirect URL
			);

			if ( empty( $sso_url ) ) {
				return new \WP_REST_Response(
					array( 'error' => 'Could not build SAML AuthnRequest URL.' ),
					500
				);
			}

			return new \WP_REST_Response( null, 302, array( 'Location' => $sso_url ) );
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
