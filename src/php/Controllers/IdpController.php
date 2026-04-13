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
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_idp' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
				array(
					'methods'             => \WP_REST_Server::DELETABLE,
					'callback'            => array( $this, 'delete_idp' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);
	}

	public function check_permission(): bool {
		return current_user_can( 'manage_options' );
	}

	public function list_idps(): \WP_REST_Response {
		$idps = array_map( array( $this, 'summary_view' ), IdpManager::all() );

		return new \WP_REST_Response( array_values( $idps ), 200 );
	}

	public function get_idp( \WP_REST_Request $request ): \WP_REST_Response {
		$id  = $request->get_param( 'id' );
		$idp = IdpManager::find( $id );

		if ( ! $idp ) {
			return new \WP_REST_Response( array( 'error' => 'IdP not found.' ), 404 );
		}

		return new \WP_REST_Response( $this->detail_view( $idp ), 200 );
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

		return new \WP_REST_Response( $this->detail_view( $sanitized ), 200 );
	}

	public function delete_idp( \WP_REST_Request $request ): \WP_REST_Response {
		$id      = $request->get_param( 'id' );
		$deleted = IdpManager::delete( $id );

		if ( ! $deleted ) {
			return new \WP_REST_Response( array( 'error' => 'IdP not found.' ), 404 );
		}

		return new \WP_REST_Response( array( 'deleted' => true ), 200 );
	}

	/**
	 * Return the minimal IdP fields required by the list views.
	 *
	 * @param array<string, mixed> $idp
	 * @return array<string, mixed>
	 */
	private function summary_view( array $idp ): array {
		return array(
			'id'            => sanitize_text_field( (string) ( $idp['id'] ?? '' ) ),
			'provider_name' => sanitize_text_field( (string) ( $idp['provider_name'] ?? '' ) ),
			'protocol'      => sanitize_key( (string) ( $idp['protocol'] ?? '' ) ),
			'domain_mapping' => array_values( array_map( 'sanitize_text_field', (array) ( $idp['domain_mapping'] ?? array() ) ) ),
			'enabled'       => ! empty( $idp['enabled'] ),
		);
	}

	/**
	 * Return the masked IdP fields required by the edit screens.
	 *
	 * @param array<string, mixed> $idp
	 * @return array<string, mixed>
	 */
	private function detail_view( array $idp ): array {
		return array(
			'id'                         => sanitize_text_field( (string) ( $idp['id'] ?? '' ) ),
			'provider_name'              => sanitize_text_field( (string) ( $idp['provider_name'] ?? '' ) ),
			'provider_family'            => sanitize_key( (string) ( $idp['provider_family'] ?? '' ) ),
			'protocol'                   => sanitize_key( (string) ( $idp['protocol'] ?? '' ) ),
			'client_id'                  => sanitize_text_field( (string) ( $idp['client_id'] ?? '' ) ),
			'client_secret'              => ! empty( $idp['client_secret'] ) ? '••••••••' : '',
			'issuer'                     => esc_url_raw( (string) ( $idp['issuer'] ?? '' ) ),
			'entity_id'                  => sanitize_text_field( (string) ( $idp['entity_id'] ?? '' ) ),
			'certificate'                => sanitize_textarea_field( (string) ( $idp['certificate'] ?? '' ) ),
			'authorization_endpoint'     => esc_url_raw( (string) ( $idp['authorization_endpoint'] ?? '' ) ),
			'token_endpoint'             => esc_url_raw( (string) ( $idp['token_endpoint'] ?? '' ) ),
			'userinfo_endpoint'          => esc_url_raw( (string) ( $idp['userinfo_endpoint'] ?? '' ) ),
			'jwks_uri'                   => esc_url_raw( (string) ( $idp['jwks_uri'] ?? '' ) ),
			'sso_url'                    => esc_url_raw( (string) ( $idp['sso_url'] ?? '' ) ),
			'domain_mapping'             => array_values( array_map( 'sanitize_text_field', (array) ( $idp['domain_mapping'] ?? array() ) ) ),
			'role_mapping'               => (array) ( $idp['role_mapping'] ?? array() ),
			'super_tenant'               => ! empty( $idp['super_tenant'] ),
			'enabled'                    => ! empty( $idp['enabled'] ),
			'override_attribute_mapping' => ! empty( $idp['override_attribute_mapping'] ),
			'custom_email_attr'          => sanitize_text_field( (string) ( $idp['custom_email_attr'] ?? '' ) ),
			'custom_first_name_attr'     => sanitize_text_field( (string) ( $idp['custom_first_name_attr'] ?? '' ) ),
			'custom_last_name_attr'      => sanitize_text_field( (string) ( $idp['custom_last_name_attr'] ?? '' ) ),
			'force_reauth'               => ! empty( $idp['force_reauth'] ),
			'end_session_endpoint'       => esc_url_raw( (string) ( $idp['end_session_endpoint'] ?? '' ) ),
			'slo_url'                    => esc_url_raw( (string) ( $idp['slo_url'] ?? '' ) ),
		);
	}
}
