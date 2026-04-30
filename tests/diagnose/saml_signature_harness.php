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

	function admin_url(): string {
		return 'https://example.test/wp-admin/';
	}

	function get_current_blog_id(): int {
		return 1;
	}

	function is_wp_error( mixed $value ): bool {
		return $value instanceof WP_Error;
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

			return 'diag-saml-1';
		}

		public static function login_error_url( string $error_code, string $reference = '' ): string {
			return 'https://example.test/wp-login.php?sso_error=' . $error_code . '&sso_error_ref=' . $reference;
		}
	}

	class FederationFlowGuard {
		/** @return array<string, mixed>|\WP_Error */
		public static function consume( string $protocol, string $flow_key ) {
			if ( 'relay-abc' !== $flow_key ) {
				return new \WP_Error( 'ea_federation_flow_missing', 'Flow missing.' );
			}

			return array(
				'idp_id'     => 'idp-saml-1',
				'request_id' => 'req-123',
				'blog_id'    => 1,
			);
		}
	}

	class CurrentSiteIdpManager {
		/** @return array<string, mixed>|null */
		public static function find_for_blog( int $blog_id, string $idp_id ): ?array {
			if ( 1 !== $blog_id || 'idp-saml-1' !== $idp_id ) {
				return null;
			}

			return array(
				'id'       => 'idp-saml-1',
				'protocol' => 'saml',
			);
		}
	}

	class EnterpriseProvisioning {
		public static function provision_and_login( array $idp, array $attributes ): bool {
			return true;
		}
	}

	class SamlSettingsFactory {
		/** @return array<string, mixed> */
		public static function build( array $idp ): array {
			return array();
		}
	}
}

namespace OneLogin\Saml2 {
	class Auth {
		/** @param array<string, mixed> $settings */
		public function __construct( array $settings ) {}

		public function processResponse( string $request_id ): void {
			// No-op for harness.
		}

		/** @return string[] */
		public function getErrors(): array {
			return array( 'invalid_signature' );
		}

		public function getLastErrorReason(): string {
			return 'Signature validation failed for Assertion.';
		}

		public function isAuthenticated(): bool {
			return false;
		}

		/** @return array<string, array<int, string>> */
		public function getAttributes(): array {
			return array();
		}

		public function getNameId(): string {
			return 'user@example.test';
		}

		public function getSessionExpiration(): int {
			return 0;
		}
	}
}

namespace {
	require_once __DIR__ . '/../../src/php/Controllers/SAML/SamlAcsController.php';

	$request = new WP_REST_Request(
		array(
			'SAMLResponse' => base64_encode( '<Response><Signature>tampered</Signature></Response>' ),
			'RelayState'   => 'relay-abc',
		)
	);

	$controller = new EnterpriseAuth\Plugin\Controllers\SAML\SamlAcsController();
	$response   = $controller->consume( $request );

	if ( 302 !== $response->status ) {
		fwrite( STDERR, "FAIL: Expected 302 redirect for SAML signature failure.\n" );
		exit( 1 );
	}

	$location = (string) ( $response->headers['Location'] ?? '' );
	if ( false === strpos( $location, 'sso_error=federation_failed' ) ) {
		fwrite( STDERR, "FAIL: Expected masked federation error redirect.\n" );
		exit( 1 );
	}

	$entry = EnterpriseAuth\Plugin\FederationErrorHandler::$entries[0] ?? null;
	if ( ! is_array( $entry ) ) {
		fwrite( STDERR, "FAIL: Expected federation failure log entry.\n" );
		exit( 1 );
	}

	$detail = (string) ( $entry['detail'] ?? '' );
	if ( false === strpos( $detail, '[DEBUG-fed-saml] [saml_assertion_invalid_signature]' ) ) {
		fwrite( STDERR, "FAIL: Expected sharp SAML diagnostic signal for invalid signature.\n" );
		exit( 1 );
	}

	fwrite( STDOUT, "PASS: SAML harness captured deterministic invalid-signature signal.\n" );
}
