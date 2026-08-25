<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds the OneLogin php-saml settings array from an IdpManager entry
 * and site-specific SP configuration.
 */
final class SamlSettingsFactory {

	/**
	 * Build the settings array expected by \OneLogin\Saml2\Auth.
	 *
	 * @param array|null $idp  Optional IdP config from IdpManager. Null for metadata-only usage.
	 * @return array<string, mixed>
	 */
	public static function build( ?array $idp = null ): array {
		$site_url = home_url( '/' );
		$acs_url  = rest_url( 'enterprise-auth/v1/saml/acs' );

		$settings = array(
			'strict'   => true,
			'debug'    => defined( 'WP_DEBUG' ) && WP_DEBUG,
			'sp'       => array(
				'entityId'                 => $site_url,
				'assertionConsumerService' => array(
					'url'     => $acs_url,
					'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
				),
				'NameIDFormat'             => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
			),
			'idp'      => array(
				'entityId'            => '',
				'singleSignOnService' => array(
					'url'     => '',
					'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
				),
				'x509cert'            => '',
			),
			'security' => array(
				'authnRequestsSigned'        => false,
				'wantAssertionsSigned'       => true,
				'wantAssertionsEncrypted'    => false,
				'wantNameIdEncrypted'        => false,
				'wantMessagesSigned'         => true,
				'destinationStrictlyMatches' => true,
				'rejectUnsolicitedResponsesWithInResponseTo' => true,
				'signatureAlgorithm'         => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
				'digestAlgorithm'            => 'http://www.w3.org/2001/04/xmlenc#sha256',
			),
		);

		if ( $idp ) {
			$settings['idp']['entityId']                   = $idp['entity_id'] ?? '';
			$settings['idp']['singleSignOnService']['url'] = $idp['sso_url'] ?? '';
			$settings['idp']['x509cert']                   = self::clean_cert( $idp['certificate'] ?? '' );

			$sp_cert = self::clean_cert( (string) ( $idp['saml_sp_certificate'] ?? '' ) );
			$sp_key  = self::clean_private_key( (string) ( $idp['saml_sp_private_key'] ?? '' ) );
			if ( '' !== $sp_cert ) {
				$settings['sp']['x509cert'] = $sp_cert;
			}
			if ( '' !== $sp_key ) {
				$settings['sp']['privateKey'] = $sp_key;
			}

			$settings['security']['authnRequestsSigned']     = ! empty( $idp['saml_authn_requests_signed'] );
			$settings['security']['wantAssertionsEncrypted'] = ! empty( $idp['saml_want_assertions_encrypted'] );
			$settings['security']['wantNameIdEncrypted']     = ! empty( $idp['saml_want_nameid_encrypted'] );
		}

		return $settings;
	}

	/**
	 * Strip PEM headers/footers and whitespace from a certificate string.
	 */
	private static function clean_cert( string $cert ): string {
		$cert = str_replace( array( '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----' ), '', $cert );
		return trim( preg_replace( '/\s+/', '', $cert ) );
	}

	private static function clean_private_key( string $key ): string {
		$key = str_replace(
			array( '-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----' ),
			'',
			$key
		);

		return trim( preg_replace( '/\s+/', '', $key ) );
	}
}
