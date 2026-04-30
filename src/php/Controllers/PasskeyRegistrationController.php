<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\CredentialRepository;
use EnterpriseAuth\Plugin\OneTimeTransient;
use EnterpriseAuth\Plugin\PasskeyEnrollmentValidator;
use EnterpriseAuth\Plugin\WebAuthnHelper;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\AuthenticatorSelectionCriteria;

/**
 * REST controller for the WebAuthn registration ceremony.
 *
 * GET  /enterprise-auth/v1/passkeys/register – return creation options (challenge)
 * POST /enterprise-auth/v1/passkeys/register – verify attestation & store credential
 */
final class PasskeyRegistrationController {

	private const NAMESPACE     = 'enterprise-auth/v1';
	private const ROUTE         = '/passkeys/register';
	private const TRANSIENT     = 'ea_webauthn_reg_';
	private const CHALLENGE_TTL = 60; // seconds
	private const USER_HANDLE_META = '_enterprise_auth_webauthn_user_handle';
	private PasskeyEnrollmentValidator $enrollment_validator;

	public function __construct( ?PasskeyEnrollmentValidator $enrollment_validator = null ) {
		$this->enrollment_validator = $enrollment_validator ?? new PasskeyEnrollmentValidator();
	}

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			self::ROUTE,
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_creation_options' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'verify_attestation' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);
	}

	/**
	 * Must be logged-in and either be an admin or be in a required step-up flow.
	 */
	public function check_permission(): bool {
		if ( ! is_user_logged_in() ) {
			return false;
		}

		if ( current_user_can( 'manage_options' ) ) {
			return true;
		}

		return \EnterpriseAuth\Plugin\PasskeyPolicy::is_step_up_required_for_user( get_current_user_id() );
	}

	/**
	 * GET – generate the PublicKeyCredentialCreationOptions.
	 */
	public function get_creation_options( \WP_REST_Request $_request ): \WP_REST_Response {
		$user    = wp_get_current_user();
		$user_id = (int) $user->ID;

		$rp        = WebAuthnHelper::rp_entity();
		$challenge = WebAuthnHelper::generate_challenge();

		// Build the user entity; the id is a stable opaque handle.
		$user_handle  = hash( 'sha256', (string) $user_id, true );
		update_user_meta( $user_id, self::USER_HANDLE_META, base64_encode( $user_handle ) );
		$display_name = $user->display_name;
		if ( '' === $display_name ) {
			$display_name = $user->user_login;
		}
		$user_entity = PublicKeyCredentialUserEntity::create(
			name: $user->user_login,
			id: $user_handle,
			displayName: $display_name,
		);

		// Algorithms: ES256 (-7) and RS256 (-257).
		$pub_key_params = array(
			PublicKeyCredentialParameters::create( 'public-key', -7 ),
			PublicKeyCredentialParameters::create( 'public-key', -257 ),
		);

		// Exclude already-registered credentials to prevent duplicates.
		$existing = CredentialRepository::find_all_for_user( $user_id );
		$exclude  = array_map(
			static fn( $src ) => $src->getPublicKeyCredentialDescriptor(),
			$existing
		);

		$authenticator_selection = AuthenticatorSelectionCriteria::create(
			authenticatorAttachment: AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
			userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
			residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
		);

		$options = PublicKeyCredentialCreationOptions::create(
			rp: $rp,
			user: $user_entity,
			challenge: $challenge,
			pubKeyCredParams: $pub_key_params,
			authenticatorSelection: $authenticator_selection,
			attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
			excludeCredentials: $exclude,
			timeout: 60000,
		);

		// Store options in a transient for verification (60 seconds TTL).
		set_transient(
			self::transient_key( $user_id ),
			WebAuthnHelper::serializer()->serialize( $options, 'json' ),
			self::CHALLENGE_TTL
		);

		$json = WebAuthnHelper::serializer()->serialize( $options, 'json' );

		return new \WP_REST_Response( json_decode( $json, true ), 200 );
	}

	/**
	 * POST – verify the attestation response and store the credential.
	 */
	public function verify_attestation( \WP_REST_Request $request ): \WP_REST_Response {
		$user    = wp_get_current_user();
		$user_id = (int) $user->ID;

		// Retrieve the stored creation options.
		$options_json = OneTimeTransient::consume( self::transient_key( $user_id ) );

		if ( ! $options_json ) {
			return $this->error_response(
				'challenge_expired',
				'Registration timed out. Start enrollment again and approve the passkey prompt within 60 seconds.'
			);
		}

		/** @var PublicKeyCredentialCreationOptions $creation_options */
		$creation_options = WebAuthnHelper::serializer()->deserialize(
			$options_json,
			PublicKeyCredentialCreationOptions::class,
			'json'
		);

		$validation = $this->enrollment_validator->validateEnrollment(
			$creation_options,
			$request->get_body()
		);

		if ( ! $validation['success'] ) {
			return $this->error_response( $validation['code'], $validation['message'] );
		}

		$credential_source = $validation['credential_source'];

		// Persist the credential.
		CredentialRepository::save(
			$credential_source,
			$user_id,
			\EnterpriseAuth\Plugin\PasskeyPolicy::compliance_status_for_new_credential( $credential_source ),
			\EnterpriseAuth\Plugin\PasskeyPolicy::current_registration_origin()
		);

		$redirect_to = \EnterpriseAuth\Plugin\PasskeyPolicy::complete_step_up_if_satisfied( $user_id );

		return new \WP_REST_Response(
			array(
				'success' => true,
				'message' => 'Passkey registered.',
				'redirect_to' => $redirect_to,
			),
			200
		);
	}

	/**
	 * Blog-scoped transient key for WebAuthn registration challenges.
	 */
	private static function transient_key( int $user_id ): string {
		$key = self::TRANSIENT . $user_id;

		if ( ! is_multisite() ) {
			return $key;
		}

		return 'ea_' . get_current_blog_id() . '_' . $key;
	}

	private function error_response( string $code, string $message ): \WP_REST_Response {
		return new \WP_REST_Response(
			array(
				'code'  => $code,
				'error' => $message,
			),
			400
		);
	}

}
