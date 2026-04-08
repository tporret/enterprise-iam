<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\IdpManager;

/**
 * Intelligent Domain Routing.
 *
 * Accepts an email address, extracts the domain, and checks if an SSO IdP
 * is configured for that domain. Returns either an SSO redirect URL or a
 * flag to proceed with local (Passkey/password) authentication.
 *
 * Route: POST /enterprise-auth/v1/route-login
 */
final class LoginRouter {

	private const NAMESPACE = 'enterprise-auth/v1';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/route-login',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'route' ),
				'permission_callback' => '__return_true',
				'args'                => array(
					'email' => array(
						'type'              => 'string',
						'required'          => true,
						'sanitize_callback' => 'sanitize_email',
					),
				),
			)
		);
	}

	/**
	 * Determine the login method for the given email.
	 */
	public function route( \WP_REST_Request $request ): \WP_REST_Response {
		$email = $request->get_param( 'email' );

		if ( ! is_email( $email ) ) {
			return new \WP_REST_Response( array( 'error' => 'Invalid email address.' ), 400 );
		}

		$parts  = explode( '@', $email );
		$domain = strtolower( $parts[1] ?? '' );

		$idp = IdpManager::find_by_domain( $domain );

		if ( ! $idp ) {
			return new \WP_REST_Response(
				array(
					'method' => 'local',
				),
				200
			);
		}

		// Even when a domain is mapped to an IdP, a WordPress account that
		// has no SSO provider binding is a local account and must log in
		// locally (password / passkey). This preserves break-glass admin
		// access and any other intentionally-local accounts on SSO domains.
		$wp_user = get_user_by( 'email', $email );
		if ( $wp_user ) {
			$existing_provider = get_user_meta( $wp_user->ID, '_enterprise_auth_sso_provider', true );
			if ( empty( $existing_provider ) ) {
				return new \WP_REST_Response(
					array(
						'method' => 'local',
					),
					200
				);
			}
		}

		// Build the SSO redirect URL based on protocol.
		$redirect_url = $this->build_redirect_url( $idp, $email );

		return new \WP_REST_Response(
			array(
				'method'        => 'sso',
				'provider_name' => $idp['provider_name'] ?? 'SSO Provider',
				'redirect_url'  => $redirect_url,
			),
			200
		);
	}

	/**
	 * Build the SSO initiation redirect URL.
	 */
	private function build_redirect_url( array $idp, string $_email ): string {
		if ( ( $idp['protocol'] ?? '' ) === 'oidc' ) {
			// Route to the dedicated OIDC Login Controller which handles
			// state/nonce generation and the Authorization Code redirect.
			return add_query_arg(
				array(
					'idp_id' => $idp['id'],
				),
				rest_url( 'enterprise-auth/v1/oidc/login' )
			);
		}

		// SAML – redirect to our SP-initiated login endpoint which
		// builds the AuthnRequest via the OneLogin toolkit.
		return add_query_arg(
			array(
				'idp_id' => $idp['id'],
			),
			rest_url( 'enterprise-auth/v1/saml/login' )
		);
	}
}
