<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialRpEntity;

/**
 * Provides shared WebAuthn ceremony helpers.
 */
final class WebAuthnHelper {

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
	 * Generate a cryptographically random challenge.
	 */
	public static function generate_challenge(): string {
		return random_bytes( 32 );
	}
}
