<?php

declare( strict_types=1 );

namespace {
	if ( ! defined( 'ABSPATH' ) ) {
		define( 'ABSPATH', __DIR__ );
	}
	if ( ! defined( 'ARRAY_A' ) ) {
		define( 'ARRAY_A', 'ARRAY_A' );
	}

	class WP_REST_Server {
		public const READABLE = 'GET';
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
	}

	class WP_REST_Response {
		public mixed $data;
		public int $status;

		public function __construct( mixed $data = null, int $status = 200 ) {
			$this->data   = $data;
			$this->status = $status;
		}
	}

	class EA_Passkey_Inventory_WPDB {
		public string $prefix = 'wp_';

		public function prepare( string $query, mixed ...$args ): string {
			return vsprintf( str_replace( '%d', '%d', $query ), $args );
		}

		public function get_results( string $query, string $output ): array {
			return array(
				array(
					'id' => 7,
					'user_id' => 12,
					'credential_id' => 'raw-credential-id-must-not-leak',
					'sign_count' => 9,
					'transports' => '["internal","hybrid"]',
					'attestation_type' => 'apple',
					'aaguid' => '00000000-0000-0000-0000-000000000000',
					'backup_eligible' => '0',
					'backup_status' => '0',
					'uv_initialized' => '1',
					'compliance_status' => 'compliant',
					'registration_origin' => 'https://example.test',
					'created_at' => '2026-05-25 12:00:00',
					'last_used_at' => '2026-05-25 12:05:00',
				),
			);
		}
	}

	$GLOBALS['wpdb'] = new EA_Passkey_Inventory_WPDB();

	function current_user_can( string $capability ): bool {
		return 'manage_options' === $capability;
	}

	function get_userdata( int $user_id ): object|false {
		if ( 12 !== $user_id ) {
			return false;
		}

		return (object) array(
			'user_login' => 'admin',
			'user_email' => 'admin@example.test',
			'display_name' => 'Admin User',
		);
	}
}

namespace {
	require_once __DIR__ . '/../../src/php/DatabaseManager.php';
	require_once __DIR__ . '/../../src/php/CredentialRepository.php';
	require_once __DIR__ . '/../../src/php/Controllers/PasskeyCredentialsController.php';

	$controller = new EnterpriseAuth\Plugin\Controllers\PasskeyCredentialsController();
	if ( ! $controller->check_permission() ) {
		fwrite( STDERR, "FAIL: Expected manage_options users to read credential inventory.\n" );
		exit( 1 );
	}

	$response = $controller->list_credentials( new WP_REST_Request( array( 'per_page' => 10 ) ) );
	if ( 200 !== $response->status ) {
		fwrite( STDERR, "FAIL: Expected 200 response.\n" );
		exit( 1 );
	}

	$item = $response->data['items'][0] ?? null;
	if ( ! is_array( $item ) ) {
		fwrite( STDERR, "FAIL: Expected one credential inventory item.\n" );
		exit( 1 );
	}

	if ( 'raw-credential-id-must-not-leak' === ( $item['credential_fingerprint'] ?? '' ) ) {
		fwrite( STDERR, "FAIL: Credential inventory leaked the raw credential ID.\n" );
		exit( 1 );
	}

	if ( 16 !== strlen( (string) ( $item['credential_fingerprint'] ?? '' ) ) ) {
		fwrite( STDERR, "FAIL: Expected a short stable credential fingerprint.\n" );
		exit( 1 );
	}

	if ( 'Admin User' !== ( $item['user']['display_name'] ?? '' ) ) {
		fwrite( STDERR, "FAIL: Expected user display metadata.\n" );
		exit( 1 );
	}

	if ( true !== ( $item['uv_initialized'] ?? null ) || false !== ( $item['backup_eligible'] ?? null ) ) {
		fwrite( STDERR, "FAIL: Expected boolean provenance fields to be normalized.\n" );
		exit( 1 );
	}

	fwrite( STDOUT, "PASS: Passkey credential inventory returns masked provenance metadata.\n" );
}