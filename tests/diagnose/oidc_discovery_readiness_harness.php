<?php

declare( strict_types=1 );

namespace {
	if ( ! defined( 'ABSPATH' ) ) {
		define( 'ABSPATH', __DIR__ );
	}

	class WP_Error {
		private string $code;
		private string $message;
		private mixed $data;

		public function __construct( string $code, string $message, mixed $data = null ) {
			$this->code    = $code;
			$this->message = $message;
			$this->data    = $data;
		}

		public function get_error_message(): string {
			return $this->message;
		}

		public function get_error_code(): string {
			return $this->code;
		}

		public function get_error_data(): mixed {
			return $this->data;
		}
	}

	class WP_REST_Request {
		/** @var array<string, mixed> */
		private array $params;

		/** @param array<string, mixed> $params */
		public function __construct( array $params = array() ) {
			$this->params = $params;
		}

		public function get_param( string $key ): mixed {
			return $this->params[ $key ] ?? null;
		}

		/** @return array<string, mixed> */
		public function get_json_params(): array {
			return $this->params;
		}
	}

	class WP_REST_Response {
		public mixed $data;
		public int $status;

		/** @param array<string, mixed> $headers */
		public function __construct( mixed $data = null, int $status = 200, array $headers = array() ) {
			$this->data   = $data;
			$this->status = $status;
		}
	}

	function current_user_can( string $capability ): bool {
		return in_array( $capability, array( 'manage_options', 'manage_network_options' ), true );
	}

	function esc_url_raw( mixed $value ): string {
		return is_string( $value ) ? trim( $value ) : '';
	}

	function is_wp_error( mixed $value ): bool {
		return $value instanceof WP_Error;
	}

	function untrailingslashit( string $value ): string {
		return rtrim( $value, '/' );
	}

	function rest_url( string $path = '' ): string {
		return 'https://wp.example.edu/wp-json/' . ltrim( $path, '/' );
	}

	function wp_remote_get( string $url, array $args = array() ): array|WP_Error {
		if ( str_ends_with( $url, '/.well-known/openid-configuration' ) ) {
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode(
					array(
						'issuer'                 => 'https://idp.example.edu/oauth2/default',
						'authorization_endpoint' => 'https://idp.example.edu/oauth2/default/v1/authorize',
						'token_endpoint'         => 'https://idp.example.edu/oauth2/default/v1/token',
						'userinfo_endpoint'      => 'https://idp.example.edu/oauth2/default/v1/userinfo',
						'jwks_uri'               => 'https://idp.example.edu/oauth2/default/v1/keys',
						'end_session_endpoint'   => 'https://idp.example.edu/oauth2/default/v1/logout',
					)
				),
			);
		}

		if ( str_ends_with( $url, '/v1/keys' ) ) {
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( array( 'keys' => array( array( 'kid' => 'signing-key-1' ) ) ) ),
			);
		}

		return new WP_Error( 'not_found', 'Unexpected URL: ' . $url, array( 'status' => 404 ) );
	}

	function wp_remote_retrieve_response_code( array $response ): int {
		return (int) ( $response['response']['code'] ?? 0 );
	}

	function wp_remote_retrieve_body( array $response ): string {
		return (string) ( $response['body'] ?? '' );
	}

	function wp_json_encode( mixed $value ): string {
		return (string) json_encode( $value );
	}
}

namespace EnterpriseAuth\Plugin {
	class IdpManager {
		public static function validate_runtime_endpoint_url( string $url, string $field ) {
			if ( '' === $url ) {
				return true;
			}

			$scheme = parse_url( $url, PHP_URL_SCHEME );
			$host   = parse_url( $url, PHP_URL_HOST );
			if ( 'https' !== $scheme || empty( $host ) ) {
				return new \WP_Error( 'enterprise_auth_invalid_idp_url', $field . ' must be a valid HTTPS URL.', array( 'status' => 400 ) );
			}

			return true;
		}
	}
}

namespace {
	require_once __DIR__ . '/../../src/php/Controllers/OIDC/OidcDiscoveryController.php';

	$controller = new EnterpriseAuth\Plugin\Controllers\OIDC\OidcDiscoveryController();

	$discovery = $controller->discover( new WP_REST_Request( array( 'issuer_url' => 'https://idp.example.edu/oauth2/default' ) ) );
	if ( 200 !== $discovery->status ) {
		fwrite( STDERR, "FAIL: Expected discovery success.\n" );
		exit( 1 );
	}

	$config = $discovery->data['config'] ?? array();
	if ( 'https://idp.example.edu/oauth2/default/v1/authorize' !== ( $config['authorization_endpoint'] ?? '' ) ) {
		fwrite( STDERR, "FAIL: Discovery did not return sanitized OIDC endpoints.\n" );
		exit( 1 );
	}

	$readiness = $controller->readiness(
		new WP_REST_Request(
			array(
				'client_id'              => 'wp-campus-client',
				'client_secret'          => 'secret',
				'issuer'                 => 'https://idp.example.edu/oauth2/default',
				'authorization_endpoint' => 'https://idp.example.edu/oauth2/default/v1/authorize',
				'token_endpoint'         => 'https://idp.example.edu/oauth2/default/v1/token',
				'userinfo_endpoint'      => 'https://idp.example.edu/oauth2/default/v1/userinfo',
				'jwks_uri'               => 'https://idp.example.edu/oauth2/default/v1/keys',
			)
		)
	);

	if ( 200 !== $readiness->status || true !== ( $readiness->data['ready'] ?? false ) ) {
		fwrite( STDERR, "FAIL: Expected readiness to pass for complete OIDC config.\n" );
		exit( 1 );
	}

	$missing_client = $controller->readiness(
		new WP_REST_Request(
			array(
				'issuer'                 => 'https://idp.example.edu/oauth2/default',
				'authorization_endpoint' => 'https://idp.example.edu/oauth2/default/v1/authorize',
				'token_endpoint'         => 'https://idp.example.edu/oauth2/default/v1/token',
				'jwks_uri'               => 'https://idp.example.edu/oauth2/default/v1/keys',
			)
		)
	);

	if ( true === ( $missing_client->data['ready'] ?? true ) ) {
		fwrite( STDERR, "FAIL: Readiness should fail without a client ID.\n" );
		exit( 1 );
	}

	fwrite( STDOUT, "PASS: OIDC discovery/readiness harness validated server-side setup checks.\n" );
}