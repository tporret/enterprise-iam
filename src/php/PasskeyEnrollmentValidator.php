<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;

/**
 * Pure validator for passkey registration enrollment flows.
 */
final class PasskeyEnrollmentValidator {

	/**
	 * @return array{success: true, credential_source: PublicKeyCredentialSource}|array{success: false, code: string, message: string}
	 */
	public function validateEnrollment( PublicKeyCredentialCreationOptions $creation_options, string $request_body ): array {
		$serializer = WebAuthnHelper::serializer();

		try {
			/** @var PublicKeyCredential $pkc */
			$pkc = $serializer->deserialize( $request_body, PublicKeyCredential::class, 'json' );
		} catch ( \Throwable $e ) {
			return array(
				'success' => false,
				'code' => 'invalid_attestation_payload',
				'message' => 'The browser returned an invalid passkey attestation payload. Try again from a current browser on a managed device.',
			);
		}

		$response = $pkc->response;
		if ( ! $response instanceof AuthenticatorAttestationResponse ) {
			return array(
				'success' => false,
				'code' => 'invalid_attestation_response',
				'message' => 'The browser did not return a valid passkey attestation response.',
			);
		}

		try {
			$credential_source = WebAuthnHelper::attestation_validator()->check(
				$response,
				$creation_options,
				WebAuthnHelper::rp_id(),
			);
			WebAuthnHelper::enforce_attestation_policy( $credential_source );
			PasskeyPolicy::enforce_device_bound_registration_policy( $credential_source );

			return array(
				'success' => true,
				'credential_source' => $credential_source,
			);
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Enterprise IAM - Passkey registration error: ' . $e->getMessage() );
			}

			$normalized_error = $this->normalize_error( $e );

			return array(
				'success' => false,
				'code' => $normalized_error['code'],
				'message' => $normalized_error['message'],
			);
		}
	}

	/**
	 * @return array{code: string, message: string}
	 */
	private function normalize_error( \Throwable $error ): array {
		if ( $error instanceof AttestationPolicyException ) {
			return array(
				'code' => $error->policy_code(),
				'message' => $error->user_message(),
			);
		}

		$message = $error->getMessage();

		if (
			str_contains( $message, 'certificate trust path' )
			|| str_contains( $message, 'direct certificate-backed attestation' )
			|| str_contains( $message, 'pinned authenticator identity' )
		) {
			return array(
				'code' => 'attestation_policy_rejected',
				'message' => 'This passkey does not provide the enterprise attestation required for enrollment. Use the built-in platform authenticator on a managed Safari device, not a roaming key or a non-verifiable passkey flow.',
			);
		}

		if ( str_contains( $message, 'local trust bundle' ) ) {
			return array(
				'code' => 'trust_bundle_mismatch',
				'message' => 'This platform authenticator is not in the current enterprise trust bundle. Launch support is limited to the current managed platform authenticator policy and does not include relaxed browser fallback paths.',
			);
		}

		if ( str_contains( $message, 'device-bound passkey' ) || str_contains( $message, 'Synced backup-eligible passkeys' ) ) {
			return array(
				'code' => 'credential_sync_not_permitted',
				'message' => 'Your organization requires a device-bound passkey on this managed device. Synced passkeys are not permitted.',
			);
		}

		return array(
			'code' => 'unsupported_authenticator',
			'message' => 'Passkey registration failed because the authenticator did not meet the current enterprise policy. Review the passkey requirements on this page and try again from a supported managed device.',
		);
	}
}
