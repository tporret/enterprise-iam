<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\IdpManager;

/**
 * REST API controller for IdP configuration CRUD.
 *
 * Namespace: enterprise-auth/v1
 * Routes:
 *   GET    /idps          – list all IdP configs
 *   POST   /idps          – create / update an IdP config
 *   DELETE /idps/(?P<id>[a-f0-9-]+) – delete an IdP config
 */
final class IdpController {

	private const NAMESPACE = 'enterprise-auth/v1';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/idps',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'list_idps' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'save_idp' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/idps/(?P<id>[a-f0-9-]+)',
			array(
				'methods'             => \WP_REST_Server::DELETABLE,
				'callback'            => array( $this, 'delete_idp' ),
				'permission_callback' => array( $this, 'check_permission' ),
			)
		);
	}

	public function check_permission(): bool {
		return current_user_can( 'manage_options' );
	}

	public function list_idps(): \WP_REST_Response {
		$idps = IdpManager::all();

		// Strip client_secret from the response for security.
		$safe = array_map(
			static function ( array $idp ): array {
				$idp['client_secret'] = ! empty( $idp['client_secret'] ) ? '••••••••' : '';
				return $idp;
			},
			$idps
		);

		return new \WP_REST_Response( array_values( $safe ), 200 );
	}

	public function save_idp( \WP_REST_Request $request ): \WP_REST_Response {
		$raw = $request->get_json_params();

		if ( empty( $raw ) || ! is_array( $raw ) ) {
			return new \WP_REST_Response( array( 'error' => 'Invalid payload.' ), 400 );
		}

		// If the client_secret is the masked placeholder, preserve the
		// real secret already stored in the database.
		if (
			! empty( $raw['id'] )
			&& ( ! isset( $raw['client_secret'] ) || '••••••••' === $raw['client_secret'] || '' === $raw['client_secret'] )
		) {
			$existing = IdpManager::find( $raw['id'] );
			if ( $existing ) {
				$raw['client_secret'] = $existing['client_secret'] ?? '';
			}
		}

		$sanitized = IdpManager::sanitize( $raw );
		if ( is_wp_error( $sanitized ) ) {
			$status = $sanitized->get_error_data( 'enterprise_auth_invalid_idp_url' );
			$status = is_array( $status ) && isset( $status['status'] ) ? (int) $status['status'] : 400;

			return new \WP_REST_Response(
				array( 'error' => $sanitized->get_error_message() ),
				$status
			);
		}

		$result = IdpManager::save( $sanitized );
		if ( is_wp_error( $result ) ) {
			$status = $result->get_error_data( 'enterprise_auth_secret_storage_failed' );
			$status = is_array( $status ) && isset( $status['status'] ) ? (int) $status['status'] : 500;

			return new \WP_REST_Response(
				array( 'error' => $result->get_error_message() ),
				$status
			);
		}

		// Never return client_secret in the response.
		$sanitized['client_secret'] = ! empty( $sanitized['client_secret'] ) ? '••••••••' : '';

		return new \WP_REST_Response( $sanitized, 200 );
	}

	public function delete_idp( \WP_REST_Request $request ): \WP_REST_Response {
		$id      = $request->get_param( 'id' );
		$deleted = IdpManager::delete( $id );

		if ( ! $deleted ) {
			return new \WP_REST_Response( array( 'error' => 'IdP not found.' ), 404 );
		}

		return new \WP_REST_Response( array( 'deleted' => true ), 200 );
	}
}
