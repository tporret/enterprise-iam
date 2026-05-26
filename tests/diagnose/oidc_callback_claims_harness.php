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

			return 'diag-oidc-claims';
		}

		public static function login_error_url( string $error_code, string $reference = '' ): string {
			return 'https://example.test/wp-login.php?sso_error=' . $error_code . '&sso_error_ref=' . $reference;
		}
	}

	class FederationFlowGuard {
		/** @return array<string, mixed> */
		public static function consume( string $protocol, string $flow_key ): array {
			return array(
				'state'         => $flow_key,
				'idp_id'        => 'oidc-idp-1',
				'nonce'         => 'nonce-123',
				'code_verifier' => 'verifier-123',
				'blog_id'       => 1,
			);
		}
	}

	class CurrentSiteIdpManager {
		public static function find_for_blog( int $blog_id, string $idp_id ): ?array {
			return array(
				'id'                     => $idp_id,
				'protocol'               => 'oidc',
				'issuer'                 => 'https://idp.example.edu/oauth2/default',
				'authorization_endpoint' => 'https://idp.example.edu/oauth2/default/v1/authorize',
				'token_endpoint'         => 'https://idp.example.edu/oauth2/default/v1/token',
				'userinfo_endpoint'      => 'https://idp.example.edu/oauth2/default/v1/userinfo',
				'jwks_uri'               => 'https://idp.example.edu/oauth2/default/v1/keys',
				'client_id'              => 'client-123',
				'client_secret'          => 'secret-123',
			);
		}
	}

	class IdpManager {
		public static function validate_runtime_oidc_configuration( array $idp ): true|\WP_Error {
			return true;
		}
	}

	class OidcTransientClient {
		/** @var array<string, mixed> */
		public static array $claims = array();
		/** @var array<string, mixed> */
		public static array $userinfo = array();
		public static bool $throw_on_authenticate = false;
		public static string $id_token = 'raw-id-token';
		/** @var array<string, mixed> */
		public static array $session_store = array();

		public function __construct( string $issuer, string $client_id, string $client_secret ) {}

		/** @param array<string, mixed> $session_store */
		public function prime_session_store( array $session_store ): void {
			self::$session_store = $session_store;
		}

		public function setRedirectURL( string $redirect_url ): void {}

		public function setCodeChallengeMethod( string $method ): void {}

		/** @param array<string, string> $params */
		public function providerConfigParam( array $params ): void {}

		public function authenticate(): void {
			if ( self::$throw_on_authenticate ) {
				throw new \Jumbojett\OpenIDConnectClientException( 'token validation failed' );
			}
		}

		public function getIdToken(): string {
			return self::$id_token;
		}

		public function getVerifiedClaims( string $claim ): mixed {
			return self::$claims[ $claim ] ?? null;
		}

		public function requestUserInfo(): object {
			return (object) self::$userinfo;
		}
	}

	class EnterpriseProvisioning {
		/** @var array<int, array{idp: array<string, mixed>, attributes: array<string, mixed>}> */
		public static array $calls = array();

		public static function provision_and_login( array $idp, array $attributes ): bool|\WP_Error {
			self::$calls[] = array(
				'idp'        => $idp,
				'attributes' => $attributes,
			);

			return true;
		}
	}
}

namespace Jumbojett {
	class OpenIDConnectClientException extends \Exception {}
}

namespace {
	require_once __DIR__ . '/../../src/php/Controllers/OIDC/OidcCallbackController.php';

	function reset_oidc_claims_harness(): void {
		EnterpriseAuth\Plugin\FederationErrorHandler::$entries = array();
		EnterpriseAuth\Plugin\EnterpriseProvisioning::$calls = array();
		EnterpriseAuth\Plugin\OidcTransientClient::$claims = array(
			'email'          => 'student@example.edu',
			'given_name'     => 'Ada',
			'family_name'    => 'Lovelace',
			'groups'         => array( 'students', 'research' ),
			'sub'            => 'oidc-subject-123',
			'iss'            => 'https://idp.example.edu/oauth2/default',
			'email_verified' => true,
		);
		EnterpriseAuth\Plugin\OidcTransientClient::$userinfo = array();
		EnterpriseAuth\Plugin\OidcTransientClient::$throw_on_authenticate = false;
		EnterpriseAuth\Plugin\OidcTransientClient::$id_token = 'raw-id-token';
		EnterpriseAuth\Plugin\OidcTransientClient::$session_store = array();
		$_REQUEST = array();
		$_SERVER['QUERY_STRING'] = '';
	}

	function run_oidc_claims_callback(): WP_REST_Response {
		$controller = new EnterpriseAuth\Plugin\Controllers\OIDC\OidcCallbackController();

		return $controller->callback(
			new WP_REST_Request(
				array(
					'code'  => 'auth-code-123',
					'state' => 'state-123',
				)
			)
		);
	}

	function assert_oidc_claims_harness( bool $condition, string $message ): void {
		if ( ! $condition ) {
			fwrite( STDERR, 'FAIL: ' . $message . "\n" );
			exit( 1 );
		}
	}

	function assert_oidc_signal( string $signal ): void {
		$entry = EnterpriseAuth\Plugin\FederationErrorHandler::$entries[0] ?? null;
		assert_oidc_claims_harness( is_array( $entry ), 'Expected federation failure log entry.' );

		$detail = (string) ( $entry['detail'] ?? '' );
		assert_oidc_claims_harness(
			false !== strpos( $detail, '[DEBUG-fed-oidc] [' . $signal . ']' ),
			'Expected diagnostic signal ' . $signal . '.'
		);
	}

	reset_oidc_claims_harness();
	$response = run_oidc_claims_callback();
	assert_oidc_claims_harness( 302 === $response->status, 'Expected success redirect response.' );
	assert_oidc_claims_harness( 'https://example.test/wp-admin/' === ( $response->headers['Location'] ?? '' ), 'Expected admin success redirect.' );
	assert_oidc_claims_harness( 1 === count( EnterpriseAuth\Plugin\EnterpriseProvisioning::$calls ), 'Expected one provisioning call.' );
	$attributes = EnterpriseAuth\Plugin\EnterpriseProvisioning::$calls[0]['attributes'];
	assert_oidc_claims_harness( 'student@example.edu' === $attributes['email'], 'Expected email claim to be provisioned.' );
	assert_oidc_claims_harness( 'oidc-subject-123' === $attributes['idp_uid'], 'Expected subject claim to be provisioned.' );
	assert_oidc_claims_harness( true === $attributes['email_verified'], 'Expected email_verified claim to be preserved.' );
	assert_oidc_claims_harness( 'raw-id-token' === $attributes['oidc_id_token'], 'Expected raw ID token to be passed for logout hint storage.' );
	assert_oidc_claims_harness( 'verifier-123' === EnterpriseAuth\Plugin\OidcTransientClient::$session_store['openid_connect_code_verifier'], 'Expected PKCE verifier to be primed.' );

	reset_oidc_claims_harness();
	EnterpriseAuth\Plugin\OidcTransientClient::$claims['email'] = null;
	EnterpriseAuth\Plugin\OidcTransientClient::$claims['groups'] = array();
	EnterpriseAuth\Plugin\OidcTransientClient::$userinfo = array(
		'email'       => 'fallback@example.edu',
		'given_name'  => 'Grace',
		'family_name' => 'Hopper',
		'groups'      => array( 'faculty' ),
	);
	$response = run_oidc_claims_callback();
	assert_oidc_claims_harness( 'https://example.test/wp-admin/' === ( $response->headers['Location'] ?? '' ), 'Expected userinfo fallback success redirect.' );
	$attributes = EnterpriseAuth\Plugin\EnterpriseProvisioning::$calls[0]['attributes'];
	assert_oidc_claims_harness( 'fallback@example.edu' === $attributes['email'], 'Expected userinfo email fallback.' );
	assert_oidc_claims_harness( array( 'faculty' ) === $attributes['groups'], 'Expected userinfo groups fallback.' );

	reset_oidc_claims_harness();
	EnterpriseAuth\Plugin\OidcTransientClient::$throw_on_authenticate = true;
	$response = run_oidc_claims_callback();
	assert_oidc_claims_harness( false !== strpos( (string) ( $response->headers['Location'] ?? '' ), 'sso_error=federation_failed' ), 'Expected token failure error redirect.' );
	assert_oidc_claims_harness( 0 === count( EnterpriseAuth\Plugin\EnterpriseProvisioning::$calls ), 'Token failure must not provision.' );
	assert_oidc_signal( 'oidc_token_exchange_failed' );

	reset_oidc_claims_harness();
	EnterpriseAuth\Plugin\OidcTransientClient::$claims['iss'] = 'https://issuer.example.org';
	$response = run_oidc_claims_callback();
	assert_oidc_claims_harness( false !== strpos( (string) ( $response->headers['Location'] ?? '' ), 'sso_error=federation_failed' ), 'Expected issuer mismatch error redirect.' );
	assert_oidc_claims_harness( 0 === count( EnterpriseAuth\Plugin\EnterpriseProvisioning::$calls ), 'Issuer mismatch must not provision.' );
	assert_oidc_signal( 'oidc_issuer_mismatch' );

	reset_oidc_claims_harness();
	EnterpriseAuth\Plugin\OidcTransientClient::$claims['email'] = '';
	$response = run_oidc_claims_callback();
	assert_oidc_claims_harness( false !== strpos( (string) ( $response->headers['Location'] ?? '' ), 'sso_error=federation_failed' ), 'Expected missing email error redirect.' );
	assert_oidc_claims_harness( 0 === count( EnterpriseAuth\Plugin\EnterpriseProvisioning::$calls ), 'Missing email must not provision.' );
	assert_oidc_signal( 'oidc_missing_valid_email' );

	fwrite( STDOUT, "PASS: OIDC callback claims harness validated success, fallback, and negative token paths.\n" );
}