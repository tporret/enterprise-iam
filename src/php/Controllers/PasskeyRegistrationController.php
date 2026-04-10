<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\CredentialRepository;
use EnterpriseAuth\Plugin\WebAuthnHelper;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
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
	 * Must be logged-in and have manage_options capability.
	 */
	public function check_permission(): bool {
		return current_user_can( 'manage_options' );
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
			authenticatorAttachment: null,
			userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
			residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
		);

		$options = PublicKeyCredentialCreationOptions::create(
			rp: $rp,
			user: $user_entity,
			challenge: $challenge,
			pubKeyCredParams: $pub_key_params,
			authenticatorSelection: $authenticator_selection,
			attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
			excludeCredentials: $exclude,
			timeout: 60000,
		);

		// Store options in a transient for verification (60 seconds TTL).
		set_transient(
			self::TRANSIENT . $user_id,
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
		$options_json = get_transient( self::TRANSIENT . $user_id );
		delete_transient( self::TRANSIENT . $user_id );

		if ( ! $options_json ) {
			return new \WP_REST_Response(
				array( 'error' => 'Challenge expired or not found. Please try again.' ),
				400
			);
		}

		$serializer = WebAuthnHelper::serializer();

		/** @var PublicKeyCredentialCreationOptions $creation_options */
		$creation_options = $serializer->deserialize(
			$options_json,
			PublicKeyCredentialCreationOptions::class,
			'json'
		);

		// Deserialize the browser's attestation response.
		$body = $request->get_body();

		try {
			/** @var PublicKeyCredential $pkc */
			$pkc = $serializer->deserialize( $body, PublicKeyCredential::class, 'json' );
		} catch ( \Throwable $e ) {
			return new \WP_REST_Response(
				array( 'error' => 'Invalid attestation payload.' ),
				400
			);
		}

		$response = $pkc->response;
		if ( ! $response instanceof AuthenticatorAttestationResponse ) {
			return new \WP_REST_Response(
				array( 'error' => 'Expected an attestation response.' ),
				400
			);
		}

		try {
			$credential_source = WebAuthnHelper::attestation_validator()->check(
				$response,
				$creation_options,
				WebAuthnHelper::rp_id(),
			);
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Enterprise IAM – Passkey registration error: ' . $e->getMessage() );
			}
			return new \WP_REST_Response(
				array( 'error' => 'Passkey registration failed. Please try again.' ),
				400
			);
		}

		// Persist the credential.
		CredentialRepository::save( $credential_source, $user_id );

		return new \WP_REST_Response(
			array(
				'success' => true,
				'message' => 'Passkey registered.',
			),
			200
		);
	}
}
