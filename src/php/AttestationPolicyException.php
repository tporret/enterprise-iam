<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Structured policy exception for WebAuthn enrollment failures.
 */
final class AttestationPolicyException extends \RuntimeException {

	public const CODE_ATTESTATION_FORMAT_REJECTED = 'attestation_format_rejected';
	public const CODE_ATTESTATION_TRUST_PATH_REQUIRED = 'attestation_trust_path_required';
	public const CODE_ATTESTATION_AAGUID_REQUIRED = 'attestation_aaguid_required';
	public const CODE_TRUST_BUNDLE_MISMATCH = 'trust_bundle_mismatch';
	public const CODE_CREDENTIAL_SYNC_NOT_PERMITTED = 'credential_sync_not_permitted';

	private string $policy_code;

	private string $user_message;

	private function __construct( string $policy_code, string $detail_message, string $user_message ) {
		parent::__construct( $detail_message );
		$this->policy_code  = $policy_code;
		$this->user_message = $user_message;
	}

	public static function attestation_format_rejected( string $detail_message = 'The authenticator returned a non-verifiable attestation format.' ): self {
		return new self(
			self::CODE_ATTESTATION_FORMAT_REJECTED,
			$detail_message,
			'This passkey does not provide verifiable enterprise attestation. Launch support is limited to Safari-based enrollment on managed Apple devices and other approved platform authenticators that return direct attestation.'
		);
	}

	public static function attestation_trust_path_required( string $detail_message = 'The authenticator attestation did not include a certificate trust path.' ): self {
		return new self(
			self::CODE_ATTESTATION_TRUST_PATH_REQUIRED,
			$detail_message,
			'This passkey could not be verified because it did not include an attestation certificate chain. Non-verifiable attestation is not accepted for managed enrollment.'
		);
	}

	public static function attestation_aaguid_required( string $detail_message = 'The authenticator did not provide a pinned authenticator identity.' ): self {
		return new self(
			self::CODE_ATTESTATION_AAGUID_REQUIRED,
			$detail_message,
			'This passkey could not be verified because the authenticator identity was missing. Use the built-in platform authenticator on a managed device.'
		);
	}

	public static function trust_bundle_mismatch( string $detail_message = 'The authenticator is not in the local enterprise trust bundle.' ): self {
		return new self(
			self::CODE_TRUST_BUNDLE_MISMATCH,
			$detail_message,
			'This platform authenticator is not in the current enterprise trust bundle. Enrollment is limited to authenticators that match the launch trust policy.'
		);
	}

	public static function credential_sync_not_permitted( string $detail_message = 'Synced backup-eligible passkeys are not permitted when device-bound mode is required.' ): self {
		return new self(
			self::CODE_CREDENTIAL_SYNC_NOT_PERMITTED,
			$detail_message,
			'Your organization requires a device-bound passkey on this managed device. Synced passkeys such as iCloud Keychain multi-device credentials are not permitted in strict mode.'
		);
	}

	public function policy_code(): string {
		return $this->policy_code;
	}

	public function user_message(): string {
		return $this->user_message;
	}
}