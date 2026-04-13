<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AppleAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\CertificateTrustPath;

/**
 * Provides shared WebAuthn ceremony helpers.
 */
final class WebAuthnHelper {

	private const NULL_AAGUID = '00000000-0000-0000-0000-000000000000';

	/**
	 * Get the Relying Party entity derived from the current host.
	 */
	public static function rp_entity(): PublicKeyCredentialRpEntity {
		$host      = self::rp_id();
		$site_name = get_bloginfo( 'name' );
		if ( '' === $site_name ) {
			$site_name = 'WordPress';
		}
		return PublicKeyCredentialRpEntity::create(
			name: $site_name,
			id: $host,
		);
	}

	/**
	 * Relying Party ID – the effective domain for WebAuthn.
	 */
	public static function rp_id(): string {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( empty( $host ) ) {
			return 'localhost';
		}

		return $host;
	}

	/**
	 * Build the AttestationStatementSupportManager.
	 */
	public static function attestation_support_manager(): AttestationStatementSupportManager {
		return new AttestationStatementSupportManager(
			array(
				new AppleAttestationStatementSupport(),
				new AndroidKeyAttestationStatementSupport(),
				new PackedAttestationStatementSupport(),
				new TPMAttestationStatementSupport(),
				new NoneAttestationStatementSupport(),
			)
		);
	}

	/**
	 * Build a Symfony serializer configured for WebAuthn.
	 */
	public static function serializer(): \Symfony\Component\Serializer\SerializerInterface {
		$factory = new WebauthnSerializerFactory( self::attestation_support_manager() );
		return $factory->create();
	}

	/**
	 * Build the CeremonyStepManagerFactory with allowed origins.
	 */
	public static function ceremony_factory(): CeremonyStepManagerFactory {
		$factory = new CeremonyStepManagerFactory();
		$factory->setAllowedOrigins( array( home_url() ) );
		$factory->setAttestationStatementSupportManager( self::attestation_support_manager() );
		$bundle = self::trust_bundle();
		$factory->enableMetadataStatementSupport( $bundle, $bundle, self::certificate_chain_validator() );
		return $factory;
	}

	/**
	 * Build the attestation (registration) validator.
	 */
	public static function attestation_validator(): AuthenticatorAttestationResponseValidator {
		return AuthenticatorAttestationResponseValidator::create(
			self::ceremony_factory()->creationCeremony()
		);
	}

	/**
	 * Build the assertion (login) validator.
	 */
	public static function assertion_validator(): AuthenticatorAssertionResponseValidator {
		return AuthenticatorAssertionResponseValidator::create(
			self::ceremony_factory()->requestCeremony()
		);
	}

	/**
	 * Enforce the plugin's strict attestation policy after ceremony validation.
	 */
	public static function enforce_attestation_policy( PublicKeyCredentialSource $credential_source ): void {
		if ( ! $credential_source->trustPath instanceof CertificateTrustPath ) {
			throw AuthenticatorResponseVerificationException::create( 'Passkey attestation did not include a certificate trust path.' );
		}

		if ( self::NULL_AAGUID === strtolower( $credential_source->aaguid->toRfc4122() ) ) {
			throw AuthenticatorResponseVerificationException::create( 'Passkey attestation did not provide a pinned authenticator identity.' );
		}

		if ( ! in_array( $credential_source->attestationType, self::allowed_attestation_types(), true ) ) {
			throw AuthenticatorResponseVerificationException::create( 'Only direct certificate-backed attestation is accepted.' );
		}

		if ( ! in_array( strtolower( $credential_source->aaguid->toRfc4122() ), self::trust_bundle()->supported_aaguids(), true ) ) {
			throw AuthenticatorResponseVerificationException::create( 'This platform authenticator is not in the local trust bundle.' );
		}
	}

	/**
	 * Generate a cryptographically random challenge.
	 */
	public static function generate_challenge(): string {
		return random_bytes( 32 );
	}

	/**
	 * @return string[]
	 */
	private static function allowed_attestation_types(): array {
		return array(
			AttestationStatement::TYPE_BASIC,
			AttestationStatement::TYPE_ATTCA,
			AttestationStatement::TYPE_ANONCA,
		);
	}

	private static function trust_bundle(): WebAuthnAttestationTrustBundle {
		static $bundle = null;

		if ( null === $bundle ) {
			$bundle = new WebAuthnAttestationTrustBundle();
		}

		return $bundle;
	}

	private static function certificate_chain_validator(): LocalCertificateChainValidator {
		static $validator = null;

		if ( null === $validator ) {
			$validator = new LocalCertificateChainValidator();
		}

		return $validator;
	}
}
