<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use Symfony\Component\Clock\NativeClock;
use Webauthn\Exception\CertificateChainException;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;

/**
 * Validates attestation certificate chains against pinned local roots.
 */
final class LocalCertificateChainValidator implements CertificateChainValidator {

	private const MAX_VALIDATION_LENGTH = 5;

	/**
	 * @param string[] $untrusted_certificates
	 * @param string[] $trusted_certificates
	 */
	public function check( array $untrusted_certificates, array $trusted_certificates ): void {
		$untrusted_certificates = CertificateToolbox::fixPEMStructures( $untrusted_certificates );
		$trusted_certificates   = CertificateToolbox::fixPEMStructures( $trusted_certificates );

		foreach ( $trusted_certificates as $trusted_certificate ) {
			if ( $this->validate_chain( $untrusted_certificates, $trusted_certificate ) ) {
				return;
			}
		}

		throw CertificateChainException::create( $untrusted_certificates, $trusted_certificates );
	}

	/**
	 * @param string[] $untrusted_certificates
	 */
	private function validate_chain( array $untrusted_certificates, string $trusted_certificate ): bool {
		$untrusted_certificate_objects = array_map(
			static fn( string $certificate ): Certificate => Certificate::fromPEM( PEM::fromString( $certificate ) ),
			array_reverse( $untrusted_certificates )
		);
		$trusted_certificate_object    = Certificate::fromPEM( PEM::fromString( $trusted_certificate ) );

		if (
			1 === count( $untrusted_certificate_objects )
			&& $untrusted_certificate_objects[0]->toPEM()->string() === $trusted_certificate_object->toPEM()->string()
		) {
			return true;
		}

		$certificate_pems = array_map(
			static fn( Certificate $certificate ): string => $certificate->toPEM()->string(),
			array_merge( array( $trusted_certificate_object ), $untrusted_certificate_objects )
		);

		if ( count( array_unique( $certificate_pems ) ) !== count( $certificate_pems ) ) {
			throw CertificateChainException::create(
				$untrusted_certificates,
				array( $trusted_certificate ),
				'Invalid certificate chain with duplicated certificates.'
			);
		}

		$config = PathValidationConfig::create( ( new NativeClock() )->now(), self::MAX_VALIDATION_LENGTH )
			->withTrustAnchor( $trusted_certificate_object );

		try {
			CertificationPath::create(
				...array_merge( array( $trusted_certificate_object ), $untrusted_certificate_objects )
			)->validate( $config );
			return true;
		} catch ( \Throwable ) {
			return false;
		}
	}
}