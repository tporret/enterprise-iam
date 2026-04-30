<?php

declare( strict_types=1 );

namespace {
	if ( ! defined( 'ABSPATH' ) ) {
		define( 'ABSPATH', __DIR__ );
	}

	class WP_Error {
		private string $code;
		private string $message;

		public function __construct( string $code, string $message ) {
			$this->code    = $code;
			$this->message = $message;
		}

		public function get_error_message(): string {
			return $this->message;
		}

		public function get_error_code(): string {
			return $this->code;
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
	}

	class WP_REST_Response {
		public mixed $data;
		public int $status;
		/** @var array<string, mixed> */
		public array $headers;

		/** @param array<string, mixed> $headers */
		public function __construct( mixed $data = null, int $status = 200, array $headers = array() ) {
			$this->data    = $data;
			$this->status  = $status;
			$this->headers = $headers;
		}
	}

	function sanitize_text_field( mixed $value ): string {
		return is_string( $value ) ? trim( $value ) : '';
	}

	function sanitize_key( mixed $value ): string {
		if ( ! is_string( $value ) ) {
			return '';
		}

		return strtolower( preg_replace( '/[^a-z0-9_\-]/', '', $value ) ?? '' );
	}

	function is_wp_error( mixed $value ): bool {
		return $value instanceof WP_Error;
	}

	function get_current_blog_id(): int {
		return 1;
	}

	function admin_url(): string {
		return 'https://example.test/wp-admin/';
	}

	function is_email( mixed $value ): bool {
		return is_string( $value ) && false !== strpos( $value, '@' );
	}

	function sanitize_email( mixed $value ): string {
		return is_string( $value ) ? trim( $value ) : '';
	}

	function esc_url_raw( mixed $value ): string {
		return is_string( $value ) ? $value : '';
	}

	function rest_url( string $path = '' ): string {
		return 'https://example.test/wp-json/' . ltrim( $path, '/' );
	}
}

namespace EnterpriseAuth\Plugin {
	class FederationErrorHandler {
		public static array $entries = array();

		/** @param array<string, mixed> $context */
		public static function log( string $protocol, string $source, string $detail, array $context = array(), ?\Throwable $exception = null ): string {
			self::$entries[] = array(
				'protocol'  => $protocol,
				'source'    => $source,
				'detail'    => $detail,
				'context'   => $context,
				'exception' => $exception,
			);

			return 'diag-oidc-1';
		}

		public static function login_error_url( string $error_code, string $reference = '' ): string {
			return 'https://example.test/wp-login.php?sso_error=' . $error_code . '&sso_error_ref=' . $reference;
		}
	}

	class FederationFlowGuard {
		/** @return array<string, mixed>|\WP_Error */
		public static function consume( string $protocol, string $flow_key ) {
			return array(
				'state'         => 'different-state',
				'idp_id'        => 'oidc-idp-1',
				'nonce'         => 'nonce-123',
				'code_verifier' => 'verifier-123',
				'blog_id'       => 1,
			);
		}
	}

	class CurrentSiteIdpManager {
		public static function find_for_blog( int $blog_id, string $idp_id ): ?array {
			return null;
		}
	}

	class IdpManager {
		public static function validate_runtime_oidc_configuration( array $idp ): true|\WP_Error {
			return true;
		}
	}

	class OidcTransientClient {
		public static int $constructed = 0;

		public function __construct( string $issuer, string $client_id, string $client_secret ) {
			self::$constructed++;
		}
	}

	class EnterpriseProvisioning {
		public static function provision_and_login( array $idp, array $attributes ): bool|\WP_Error {
			return true;
		}
	}
}

namespace Jumbojett {
	class OpenIDConnectClientException extends \Exception {}
}

namespace {
	require_once __DIR__ . '/../../src/php/Controllers/OIDC/OidcCallbackController.php';

	$request = new WP_REST_Request(
		array(
			'code'  => 'auth-code-123',
			'state' => 'expected-state',
		)
	);

	$controller = new EnterpriseAuth\Plugin\Controllers\OIDC\OidcCallbackController();
	$response   = $controller->callback( $request );

	if ( 302 !== $response->status ) {
		fwrite( STDERR, "FAIL: Expected 302 redirect for OIDC state mismatch.\n" );
		exit( 1 );
	}

	$location = (string) ( $response->headers['Location'] ?? '' );
	if ( false === strpos( $location, 'sso_error=federation_failed' ) ) {
		fwrite( STDERR, "FAIL: Expected masked federation error redirect.\n" );
		exit( 1 );
	}

	if ( 0 !== EnterpriseAuth\Plugin\OidcTransientClient::$constructed ) {
		fwrite( STDERR, "FAIL: OIDC HTTP client should not be constructed on state mismatch.\n" );
		exit( 1 );
	}

	$entry = EnterpriseAuth\Plugin\FederationErrorHandler::$entries[0] ?? null;
	if ( ! is_array( $entry ) ) {
		fwrite( STDERR, "FAIL: Expected federation failure log entry.\n" );
		exit( 1 );
	}

	$detail = (string) ( $entry['detail'] ?? '' );
	if ( false === strpos( $detail, '[DEBUG-fed-oidc] [oidc_state_mismatch]' ) ) {
		fwrite( STDERR, "FAIL: Expected sharp OIDC diagnostic signal for state mismatch.\n" );
		exit( 1 );
	}

	fwrite( STDOUT, "PASS: OIDC harness captured deterministic state-mismatch signal with zero network calls.\n" );
}
