<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\CredentialRepository;

/**
 * REST controller for administrator passkey credential provenance.
 */
final class PasskeyCredentialsController {

	private const NAMESPACE = 'enterprise-auth/v1';
	private const ROUTE     = '/passkeys/credentials';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			self::ROUTE,
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'list_credentials' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);
	}

	public function check_permission(): bool {
		return current_user_can( 'manage_options' );
	}

	public function list_credentials( \WP_REST_Request $request ): \WP_REST_Response {
		$limit       = (int) ( $request->get_param( 'per_page' ) ? $request->get_param( 'per_page' ) : 100 );
		$credentials = CredentialRepository::credential_inventory( $limit );

		return new \WP_REST_Response(
			array(
				'items' => $credentials,
				'total' => count( $credentials ),
			),
			200
		);
	}
}
