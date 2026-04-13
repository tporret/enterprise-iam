<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\Statement\StatusReport;
use Webauthn\MetadataService\Statement\VerificationMethodANDCombinations;
use Webauthn\MetadataService\Statement\VerificationMethodDescriptor;
use Webauthn\MetadataService\Statement\Version;
use Webauthn\MetadataService\StatusReportRepository;

/**
 * Local attestation trust bundle for platform authenticators we pin explicitly.
 */
final class WebAuthnAttestationTrustBundle implements MetadataStatementRepository, StatusReportRepository {

	private const WINDOWS_HELLO_HARDWARE_AAGUID = '08987058-cadc-4b81-b6e1-30de50dcbe96';
	private const WINDOWS_HELLO_VBS_AAGUID      = '9ddd1817-af5a-4672-a2b9-3e3dd95000a9';
	private const ANDROID_AUTHENTICATOR_AAGUID  = 'b93fd961-f2e6-462f-b122-82002247de78';

	private const MICROSOFT_TPM_ROOT_2014 = 'MIIF9TCCA92gAwIBAgIQXbYwTgy/J79JuMhpUB5dyzANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE2MDQGA1UEAxMtTWljcm9zb2Z0IFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE0MB4XDTE0MTIxMDIxMzExOVoXDTM5MTIxMDIxMzkyOFowgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJ+n+bnKt/JHIRC/oI/xgkgsYdPzP0gpvduDA2GbRtth+L4WUyoZKGBw7uz5bjjP8Aql4YExyjR3EZQ4LqnZChMpoCofbeDR4MjCE1TGwWghGpS0mM3GtWD9XiME4rE2K0VW3pdN0CLzkYbvZbs2wQTFfE62yNQiDjyHFWAZ4BQH4eWa8wrDMUxIAneUCpU6zCwM+l6Qh4ohX063BHzXlTSTc1fDsiPaKuMMjWjK9vp5UHFPa+dMAWr6OljQZPFIg3aZ4cUfzS9y+n77Hs1NXPBn6E4Db679z4DThIXyoKeZTv1aaWOWl/exsDLGt2mTMTyykVV8uD1eRjYriFpmoRDwJKAEMOfaURarzp7hka9TOElGyD2gOV4Fscr2MxAYCywLmOLzA4VDSYLuKAhPSp7yawET30AvY1HRfMwBxetSqWP2+yZRNYJlHpor5QTuRDgzR+Zej+aWx6rWNYx43kLthozeVJ3QCsD5iEI/OZlmWn5WYf7O8LB/1A7scrYv44FD8ck3Z+hxXpkklAsjJMsHZa9mBqh+VR1AicX4uZG8m16x65ZU2uUpBa3rn8CTNmw17ZHOiuSWJtS9+PrZVA8ljgf4QgA1g6NPOEiLG2fn8Gm+r5Ak+9tqv72KDd2FPBJ7Xx4stYj/WjNPtEUhW4rcLK3ktLfcy6ea7Rocw5y5AgMBAAGjUTBPMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR6jArOL0hiF+KU0a5VwVLscXSkVjAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQsFAAOCAgEAW4ioo1+J9VWC0UntSBXcXRm1ePTVamtsxVy/GpP4EmJd3Ub53JzNBfYdgfUL51CppS3ZY6BoagB+DqoA2GbSL+7sFGHBl5ka6FNelrwsH6VVw4xV/8klIjmqOyfatPYsz0sUdZev+reeiGpKVoXrK6BDnUU27/mgPtem5YKWvHB/soofUrLKzZV3WfGdx9zBr8V0xW6vO3CKaqkqU9y6EsQw34n7eJCbEVVQ8VdFd9iV1pmXwaBAfBwkviPTKEP9Cm+zbFIOLr3V3CL9hJj+gkTUuXWlJJ6wVXEG5i4rIbLAV59UrW4LonP+seqvWMJYUFxu/niF0R3fSGM+NU11DtBVkhRZt1u0kFhZqjDz1dWyfT/N7Hke3WsDqUFsBi+8SEw90rWx2aUkLvKo83oU4Mx4na+2I3l9F2a2VNGk4K7l3a00g51miPiq0Da0jqw30PaLluTMTGY5+RnZVh50JD6nk+Ea3wRkU8aiYFnpIxfKBZ72whmYYa/egj9IKeqpR0vuLebbU0fJBf880K1jWD3Z5SFyJXo057Mv0OPw5mttytE585ZIy5JsaRXlsOoWGRXE3kUT/MKR1UoAgR54c8Bsh+9Dq2wqIK9mRn15zvBDeyHG6+czurLopziOUeWokxZN1syrEdKlhFoPYavm6t+PzIcpdxZwHA+V3jLJPfI=';
	private const GOOGLE_KEY_ATTESTATION_CA1 = 'MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEcMBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDETMBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0ExMRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCtG/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepAMAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifHEUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeYuR2zh/80lQyu9vAFCj6E4AXc+osmRg==';

	/** @var array<string, MetadataStatement> */
	private array $statements = array();

	/** @var array<string, StatusReport[]> */
	private array $status_reports = array();

	public function __construct() {
		$this->bootstrap();
	}

	public function findOneByAAGUID( string $aaguid ): ?MetadataStatement {
		return $this->statements[ self::normalize_aaguid( $aaguid ) ] ?? null;
	}

	/**
	 * @return StatusReport[]
	 */
	public function findStatusReportsByAAGUID( string $aaguid ): array {
		return $this->status_reports[ self::normalize_aaguid( $aaguid ) ] ?? array();
	}

	/**
	 * @return string[]
	 */
	public function supported_aaguids(): array {
		return array_keys( $this->statements );
	}

	private function bootstrap(): void {
		$this->statements = array(
			self::WINDOWS_HELLO_HARDWARE_AAGUID => $this->metadata_statement(
				self::WINDOWS_HELLO_HARDWARE_AAGUID,
				'Windows Hello Hardware Authenticator',
				19042,
				array( 'rsassa_pkcsv15_sha256_raw' ),
				array( MetadataStatement::ATTESTATION_BASIC_SURROGATE, MetadataStatement::ATTESTATION_ATTCA ),
				array(
					VerificationMethodDescriptor::USER_VERIFY_FACEPRINT_INTERNAL,
					VerificationMethodDescriptor::USER_VERIFY_EYEPRINT_INTERNAL,
					VerificationMethodDescriptor::USER_VERIFY_PASSCODE_INTERNAL,
					VerificationMethodDescriptor::USER_VERIFY_FINGERPRINT_INTERNAL,
				),
				array( MetadataStatement::KEY_PROTECTION_HARDWARE ),
				array( MetadataStatement::MATCHER_PROTECTION_SOFTWARE ),
				array( self::MICROSOFT_TPM_ROOT_2014 )
			),
			self::WINDOWS_HELLO_VBS_AAGUID      => $this->metadata_statement(
				self::WINDOWS_HELLO_VBS_AAGUID,
				'Windows Hello VBS Hardware Authenticator',
				19042,
				array( 'rsassa_pkcsv15_sha256_raw' ),
				array( MetadataStatement::ATTESTATION_ATTCA, MetadataStatement::ATTESTATION_BASIC_SURROGATE ),
				array(
					VerificationMethodDescriptor::USER_VERIFY_PASSCODE_INTERNAL,
					VerificationMethodDescriptor::USER_VERIFY_EYEPRINT_INTERNAL,
					VerificationMethodDescriptor::USER_VERIFY_FINGERPRINT_INTERNAL,
					VerificationMethodDescriptor::USER_VERIFY_FACEPRINT_INTERNAL,
				),
				array( MetadataStatement::KEY_PROTECTION_HARDWARE, MetadataStatement::KEY_PROTECTION_TEE ),
				array( MetadataStatement::MATCHER_PROTECTION_TEE ),
				array( self::MICROSOFT_TPM_ROOT_2014 )
			),
			self::ANDROID_AUTHENTICATOR_AAGUID  => $this->metadata_statement(
				self::ANDROID_AUTHENTICATOR_AAGUID,
				'Android Authenticator',
				1,
				array( 'secp256r1_ecdsa_sha256_raw' ),
				array( MetadataStatement::ATTESTATION_BASIC_FULL ),
				array(
					VerificationMethodDescriptor::USER_VERIFY_PASSCODE_INTERNAL,
					VerificationMethodDescriptor::USER_VERIFY_FINGERPRINT_INTERNAL,
					VerificationMethodDescriptor::USER_VERIFY_FACEPRINT_INTERNAL,
					VerificationMethodDescriptor::USER_VERIFY_PATTERN_INTERNAL,
				),
				array( MetadataStatement::KEY_PROTECTION_HARDWARE, MetadataStatement::KEY_PROTECTION_TEE ),
				array( MetadataStatement::MATCHER_PROTECTION_TEE ),
				array( self::GOOGLE_KEY_ATTESTATION_CA1 )
			),
		);

		$this->status_reports = array(
			self::WINDOWS_HELLO_HARDWARE_AAGUID => array(
				$this->status_report( 'FIDO_CERTIFIED_L1', '2020-08-05', 'Windows Hello Hardware Authenticator', 'FIDO20020190418002', '1.3.6', '1.1.0' ),
				$this->status_report( 'FIDO_CERTIFIED', '2020-08-05' ),
			),
			self::WINDOWS_HELLO_VBS_AAGUID      => array(
				$this->status_report( 'FIDO_CERTIFIED_L1', '2020-08-05', 'Windows Hello VBS Hardware Authenticator', 'FIDO20020190418001', '1.3.6', '1.1.0' ),
				$this->status_report( 'FIDO_CERTIFIED', '2020-08-05' ),
			),
			self::ANDROID_AUTHENTICATOR_AAGUID  => array(
				$this->status_report( 'FIDO_CERTIFIED_L1', '2020-08-20', 'Android SafetyNet Authenticator', 'FIDO20020190225001', '1.3.6', '1.1.0' ),
				$this->status_report( 'FIDO_CERTIFIED', '2020-08-05', 'Android SafetyNet Authenticator', 'FIDO20020190225001', '1.3.6', '1.1.0' ),
			),
		);
	}

	/**
	 * @param string[] $authentication_algorithms
	 * @param string[] $attestation_types
	 * @param string[] $verification_methods
	 * @param string[] $key_protection
	 * @param string[] $matcher_protection
	 * @param string[] $roots
	 */
	private function metadata_statement(
		string $aaguid,
		string $description,
		int $authenticator_version,
		array $authentication_algorithms,
		array $attestation_types,
		array $verification_methods,
		array $key_protection,
		array $matcher_protection,
		array $roots
	): MetadataStatement {
		return MetadataStatement::create(
			description: $description,
			authenticatorVersion: $authenticator_version,
			protocolFamily: 'fido2',
			schema: 3,
			upv: array( Version::create( 1, 0 ) ),
			authenticationAlgorithms: $authentication_algorithms,
			publicKeyAlgAndEncodings: array( MetadataStatement::ALG_KEY_COSE ),
			attestationTypes: $attestation_types,
			userVerificationDetails: self::verification_details( $verification_methods ),
			matcherProtection: $matcher_protection,
			tcDisplay: array(),
			attestationRootCertificates: $roots,
			aaguid: $aaguid,
			keyProtection: $key_protection,
			isKeyRestricted: false,
			attachmentHint: array( MetadataStatement::ATTACHMENT_HINT_INTERNAL ),
		);
	}

	private function status_report(
		string $status,
		?string $effective_date,
		?string $descriptor = null,
		?string $certificate_number = null,
		?string $policy_version = null,
		?string $requirements_version = null
	): StatusReport {
		return StatusReport::create(
			$status,
			$effective_date,
			null,
			null,
			$descriptor,
			$certificate_number,
			$policy_version,
			$requirements_version
		);
	}

	/**
	 * @param string[] $verification_methods
	 * @return VerificationMethodANDCombinations[]
	 */
	private static function verification_details( array $verification_methods ): array {
		return array_map(
			static fn( string $method ): VerificationMethodANDCombinations => VerificationMethodANDCombinations::create(
				array( VerificationMethodDescriptor::create( $method ) )
			),
			$verification_methods
		);
	}

	private static function normalize_aaguid( string $aaguid ): string {
		return strtolower( $aaguid );
	}
}