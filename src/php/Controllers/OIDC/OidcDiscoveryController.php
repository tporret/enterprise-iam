<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers\OIDC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\IdpManager;

/**
 * Server-side OpenID Provider discovery for OIDC IdP setup.
 */
final class OidcDiscoveryController {

	private const NAMESPACE = 'enterprise-auth/v1';
	private const ROUTE     = '/oidc/discovery';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			self::ROUTE,
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'discover' ),
					'permission_callback' => array( $this, 'check_permission' ),
					'args'                => array(
						'issuer_url' => array(
							'type'              => 'string',
							'required'          => true,
							'sanitize_callback' => 'esc_url_raw',
						),
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/oidc/readiness',
			array(
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'readiness' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);
	}

	public function check_permission(): bool {
		return current_user_can( 'manage_options' ) || current_user_can( 'manage_network_options' );
	}

	public function discover( \WP_REST_Request $request ): \WP_REST_Response {
		$issuer_url    = trim( (string) $request->get_param( 'issuer_url' ) );
		$discovery_url = $this->discovery_url( $issuer_url );

		if ( '' === $discovery_url ) {
			return new \WP_REST_Response( array( 'error' => 'Enter a valid issuer or discovery URL.' ), 400 );
		}

		$url_validation = IdpManager::validate_runtime_endpoint_url( $discovery_url, 'runtime_endpoint' );
		if ( is_wp_error( $url_validation ) ) {
			return $this->error_response( $url_validation );
		}

		$response = wp_remote_get(
			$discovery_url,
			array(
				'timeout'     => 10,
				'redirection' => 0,
				'headers'     => array(
					'Accept' => 'application/json',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return new \WP_REST_Response(
				array( 'error' => 'OpenID Discovery request failed: ' . $response->get_error_message() ),
				502
			);
		}

		$status = (int) wp_remote_retrieve_response_code( $response );
		if ( $status < 200 || $status >= 300 ) {
			return new \WP_REST_Response(
				array( 'error' => 'OpenID Discovery returned HTTP ' . $status . '.' ),
				502
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) ) {
			return new \WP_REST_Response( array( 'error' => 'OpenID Discovery did not return valid JSON.' ), 502 );
		}

		$document = $this->sanitize_document( $data );
		$required = $this->validate_required_fields( $document );
		if ( is_wp_error( $required ) ) {
			return $this->error_response( $required );
		}

		$endpoints = $this->validate_discovered_endpoints( $document );
		if ( is_wp_error( $endpoints ) ) {
			return $this->error_response( $endpoints );
		}

		return new \WP_REST_Response(
			array(
				'discovery_url' => $discovery_url,
				'config'        => $document,
				'checks'        => $this->build_checks( $issuer_url, $document ),
			),
			200
		);
	}

	public function readiness( \WP_REST_Request $request ): \WP_REST_Response {
		$raw = $request->get_json_params();
		if ( empty( $raw ) || ! is_array( $raw ) ) {
			return new \WP_REST_Response( array( 'error' => 'Invalid payload.' ), 400 );
		}

		$checks = $this->readiness_checks( $raw );
		$ready  = ! array_filter(
			$checks,
			static fn( array $check ): bool => 'fail' === ( $check['status'] ?? '' )
		);

		return new \WP_REST_Response(
			array(
				'ready'        => $ready,
				'redirect_uri' => rest_url( self::NAMESPACE . '/oidc/callback' ),
				'checks'       => array_values( $checks ),
			),
			200
		);
	}

	private function discovery_url( string $issuer_url ): string {
		$issuer_url = trim( $issuer_url );
		if ( '' === $issuer_url ) {
			return '';
		}

		$issuer_url = untrailingslashit( $issuer_url );
		if ( str_ends_with( $issuer_url, '/.well-known/openid-configuration' ) ) {
			return $issuer_url;
		}

		return $issuer_url . '/.well-known/openid-configuration';
	}

	/**
	 * @param array<string, mixed> $data
	 * @return array<string, mixed>
	 */
	private function sanitize_document( array $data ): array {
		$string_fields = array(
			'issuer',
			'authorization_endpoint',
			'token_endpoint',
			'userinfo_endpoint',
			'jwks_uri',
			'end_session_endpoint',
		);

		$document = array();
		foreach ( $string_fields as $field ) {
			$document[ $field ] = isset( $data[ $field ] ) && is_string( $data[ $field ] )
				? esc_url_raw( $data[ $field ] )
				: '';
		}

		return $document;
	}

	/**
	 * @param array<string, mixed> $document
	 * @return true|\WP_Error
	 */
	private function validate_required_fields( array $document ) {
		foreach ( array( 'issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri' ) as $field ) {
			if ( empty( $document[ $field ] ) ) {
				return new \WP_Error(
					'enterprise_auth_oidc_discovery_incomplete',
					'OpenID Discovery response is missing ' . $field . '.',
					array( 'status' => 502 )
				);
			}
		}

		return true;
	}

	/**
	 * @param array<string, mixed> $document
	 * @return true|\WP_Error
	 */
	private function validate_discovered_endpoints( array $document ) {
		$fields = array(
			'issuer',
			'authorization_endpoint',
			'token_endpoint',
			'userinfo_endpoint',
			'jwks_uri',
			'end_session_endpoint',
		);

		foreach ( $fields as $field ) {
			$validation = IdpManager::validate_runtime_endpoint_url( (string) ( $document[ $field ] ?? '' ), $field );
			if ( is_wp_error( $validation ) ) {
				return $validation;
			}
		}

		return true;
	}

	/**
	 * @param array<string, mixed> $document
	 * @return array<int, array<string, string>>
	 */
	private function build_checks( string $requested_issuer, array $document ): array {
		$checks = array(
			array(
				'code'    => 'discovery_document_valid',
				'status'  => 'pass',
				'message' => 'OpenID Discovery document contains the required OIDC endpoints.',
			),
			array(
				'code'    => 'runtime_endpoints_valid',
				'status'  => 'pass',
				'message' => 'Discovered runtime endpoints use valid public HTTPS URLs.',
			),
		);

		$requested_issuer = untrailingslashit( $requested_issuer );
		if ( str_ends_with( $requested_issuer, '/.well-known/openid-configuration' ) ) {
			$requested_issuer = untrailingslashit( substr( $requested_issuer, 0, - strlen( '/.well-known/openid-configuration' ) ) );
		}

		$discovered_issuer = untrailingslashit( (string) ( $document['issuer'] ?? '' ) );
		if ( '' !== $requested_issuer && '' !== $discovered_issuer && $requested_issuer !== $discovered_issuer ) {
			$checks[] = array(
				'code'    => 'issuer_match',
				'status'  => 'warning',
				'message' => 'Discovered issuer differs from the URL entered. Use the discovered issuer value when saving this IdP.',
			);
		} else {
			$checks[] = array(
				'code'    => 'issuer_match',
				'status'  => 'pass',
				'message' => 'Discovered issuer matches the URL entered.',
			);
		}

		return $checks;
	}

	/**
	 * @param array<string, mixed> $raw
	 * @return array<int, array<string, string>>
	 */
	private function readiness_checks( array $raw ): array {
		$checks = array();

		$this->add_check(
			$checks,
			'client_id_present',
			'' !== trim( (string) ( $raw['client_id'] ?? '' ) ) ? 'pass' : 'fail',
			'' !== trim( (string) ( $raw['client_id'] ?? '' ) )
				? 'Client ID is configured.'
				: 'Client ID is required before OIDC login can run.'
		);

		$client_secret = trim( (string) ( $raw['client_secret'] ?? '' ) );
		$this->add_check(
			$checks,
			'client_secret_present',
			'' !== $client_secret ? 'pass' : 'warning',
			'' !== $client_secret
				? 'Client secret is present or preserved from the saved IdP.'
				: 'Client secret is empty. Save a secret before testing real login.'
		);

		foreach ( array( 'issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri' ) as $field ) {
			$value = trim( (string) ( $raw[ $field ] ?? '' ) );
			if ( '' === $value ) {
				$this->add_check( $checks, $field . '_present', 'fail', $field . ' is required.' );
				continue;

			}

			$validation = IdpManager::validate_runtime_endpoint_url( $value, $field );
			$this->add_check(
				$checks,
				$field . '_valid',
				is_wp_error( $validation ) ? 'fail' : 'pass',
				is_wp_error( $validation ) ? $validation->get_error_message() : $field . ' is a valid public HTTPS URL.'
			);
		}

		$userinfo_endpoint = trim( (string) ( $raw['userinfo_endpoint'] ?? '' ) );
		if ( '' === $userinfo_endpoint ) {
			$this->add_check( $checks, 'userinfo_endpoint_present', 'warning', 'UserInfo endpoint is empty. Login can still succeed if required claims are in the ID token.' );
		} else {
			$validation = IdpManager::validate_runtime_endpoint_url( $userinfo_endpoint, 'userinfo_endpoint' );
			$this->add_check(
				$checks,
				'userinfo_endpoint_valid',
				is_wp_error( $validation ) ? 'fail' : 'pass',
				is_wp_error( $validation ) ? $validation->get_error_message() : 'UserInfo endpoint is a valid public HTTPS URL.'
			);
		}

		$end_session_endpoint = trim( (string) ( $raw['end_session_endpoint'] ?? '' ) );
		if ( '' !== $end_session_endpoint ) {
			$validation = IdpManager::validate_runtime_endpoint_url( $end_session_endpoint, 'end_session_endpoint' );
			$this->add_check(
				$checks,
				'end_session_endpoint_valid',
				is_wp_error( $validation ) ? 'fail' : 'pass',
				is_wp_error( $validation ) ? $validation->get_error_message() : 'End Session endpoint is a valid public HTTPS URL.'
			);
		}

		$this->add_jwks_check( $checks, trim( (string) ( $raw['jwks_uri'] ?? '' ) ) );

		return $checks;
	}

	/**
	 * @param array<int, array<string, string>> $checks
	 */
	private function add_jwks_check( array &$checks, string $jwks_uri ): void {
		if ( '' === $jwks_uri ) {
			return;
		}

		$validation = IdpManager::validate_runtime_endpoint_url( $jwks_uri, 'jwks_uri' );
		if ( is_wp_error( $validation ) ) {
			return;
		}

		$response = wp_remote_get(
			$jwks_uri,
			array(
				'timeout'     => 10,
				'redirection' => 0,
				'headers'     => array(
					'Accept' => 'application/json',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->add_check( $checks, 'jwks_fetch', 'fail', 'JWKS fetch failed: ' . $response->get_error_message() );
			return;
		}

		$status = (int) wp_remote_retrieve_response_code( $response );
		if ( $status < 200 || $status >= 300 ) {
			$this->add_check( $checks, 'jwks_fetch', 'fail', 'JWKS endpoint returned HTTP ' . $status . '.' );
			return;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || empty( $data['keys'] ) || ! is_array( $data['keys'] ) ) {
			$this->add_check( $checks, 'jwks_fetch', 'fail', 'JWKS endpoint did not return a keys array.' );
			return;
		}

		$this->add_check( $checks, 'jwks_fetch', 'pass', 'JWKS endpoint returned signing keys.' );
	}

	/**
	 * @param array<int, array<string, string>> $checks
	 */
	private function add_check( array &$checks, string $code, string $status, string $message ): void {
		$checks[] = array(
			'code'    => $code,
			'status'  => $status,
			'message' => $message,
		);
	}

	private function error_response( \WP_Error $error ): \WP_REST_Response {
		$data   = $error->get_error_data();
		$status = is_array( $data ) && isset( $data['status'] ) ? (int) $data['status'] : 400;

		return new \WP_REST_Response( array( 'error' => $error->get_error_message() ), $status );
	}
}