<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\CredentialRepository;
use EnterpriseAuth\Plugin\AuditLogger;
use EnterpriseAuth\Plugin\OneTimeTransient;
use EnterpriseAuth\Plugin\PasskeyStepUp;
use EnterpriseAuth\Plugin\WebAuthnHelper;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;

final class PasskeyStepUpController {

	private const NAMESPACE     = 'enterprise-auth/v1';
	private const ROUTE         = '/passkeys/step-up';
	private const TRANSIENT     = 'ea_webauthn_stepup_';
	private const CHALLENGE_TTL = 60;

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			self::ROUTE,
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_request_options' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'verify_assertion' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);
	}

	public function check_permission(): bool {
		return is_user_logged_in() && current_user_can( 'read' );
	}

	public function get_request_options( \WP_REST_Request $_request ): \WP_REST_Response {
		$user_id = get_current_user_id();
		$sources = CredentialRepository::find_all_for_user( $user_id );

		if ( array() === $sources ) {
			return new \WP_REST_Response(
				array(
					'code'  => 'passkey_required',
					'error' => __( 'Register a passkey before changing enterprise IAM configuration.', 'enterprise-auth' ),
				),
				409
			);
		}

		$options = PublicKeyCredentialRequestOptions::create(
			challenge: WebAuthnHelper::generate_challenge(),
			rpId: WebAuthnHelper::rp_id(),
			allowCredentials: array_map(
				static fn( $source ) => $source->getPublicKeyCredentialDescriptor(),
				$sources
			),
			userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
			timeout: 60000,
		);

		$session_key = bin2hex( random_bytes( 16 ) );
		set_transient(
			self::transient_key( $user_id, $session_key ),
			WebAuthnHelper::serializer()->serialize( $options, 'json' ),
			self::CHALLENGE_TTL
		);

		$data                = json_decode( WebAuthnHelper::serializer()->serialize( $options, 'json' ), true );
		$data['session_key'] = $session_key;

		return new \WP_REST_Response( $data, 200 );
	}

	public function verify_assertion( \WP_REST_Request $request ): \WP_REST_Response {
		$user_id     = get_current_user_id();
		$body        = json_decode( $request->get_body(), true );
		$session_key = sanitize_text_field( (string) ( $body['session_key'] ?? '' ) );

		if ( '' === $session_key ) {
			return $this->failure_response( 'missing_session_key', 'Missing session key.' );
		}

		$options_json = OneTimeTransient::consume( self::transient_key( $user_id, $session_key ) );
		if ( ! $options_json ) {
			return $this->failure_response( 'challenge_expired', 'Challenge expired or not found.' );
		}

		$serializer = WebAuthnHelper::serializer();
		/** @var PublicKeyCredentialRequestOptions $request_options */
		$request_options = $serializer->deserialize( $options_json, PublicKeyCredentialRequestOptions::class, 'json' );

		unset( $body['session_key'] );
		try {
			/** @var PublicKeyCredential $public_key_credential */
			$public_key_credential = $serializer->deserialize( wp_json_encode( $body ), PublicKeyCredential::class, 'json' );
		} catch ( \Throwable $e ) {
			return $this->failure_response( 'invalid_assertion_payload', 'Invalid assertion payload.' );
		}

		$response = $public_key_credential->response;
		if ( ! $response instanceof AuthenticatorAssertionResponse ) {
			return $this->failure_response( 'unexpected_response_type', 'Expected an assertion response.' );
		}

		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		$credential_source = CredentialRepository::find_by_credential_id( $public_key_credential->rawId );
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		$credential_metadata = CredentialRepository::find_metadata_by_credential_id( $public_key_credential->rawId );
		if ( ! $credential_source || ! $credential_metadata || $user_id !== (int) $credential_metadata['user_id'] ) {
			return $this->failure_response( 'credential_not_available', 'Credential not available for this user.', 403 );
		}

		try {
			$updated_source = WebAuthnHelper::assertion_validator()->check(
				$credential_source,
				$response,
				$request_options,
				WebAuthnHelper::rp_id(),
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				$credential_source->userHandle,
			);
		} catch ( \Throwable $e ) {
			return $this->failure_response( 'assertion_validation_failed', 'Passkey confirmation failed. Please try again.' );
		}

		CredentialRepository::record_successful_assertion(
			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			$updated_source->publicKeyCredentialId,
			$updated_source->counter
		);
		PasskeyStepUp::mark_verified( $user_id );
		AuditLogger::record(
			'passkey_step_up_success',
			array(
				'source'  => 'passkey',
				'result'  => 'success',
				'user_id' => $user_id,
			)
		);

		return new \WP_REST_Response(
			array(
				'success' => true,
				'ttl'     => PasskeyStepUp::ttl(),
			),
			200
		);
	}

	private static function transient_key( int $user_id, string $session_key ): string {
		$key = self::TRANSIENT . $user_id . '_' . sanitize_text_field( $session_key );

		if ( ! is_multisite() ) {
			return $key;
		}

		return 'ea_' . get_current_blog_id() . '_' . $key;
	}

	private function failure_response( string $reason, string $message, int $status = 400 ): \WP_REST_Response {
		AuditLogger::record(
			'passkey_step_up_failed',
			array(
				'source' => 'passkey',
				'result' => 'failure',
				'reason' => $reason,
			)
		);

		return new \WP_REST_Response( array( 'error' => $message ), $status );
	}
}
