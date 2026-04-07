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

		$settings = [
			'strict' => true,
			'debug'  => defined( 'WP_DEBUG' ) && WP_DEBUG,
			'sp'     => [
				'entityId'                 => $site_url,
				'assertionConsumerService' => [
					'url'     => $acs_url,
					'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
				],
				'NameIDFormat'             => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
			],
			'idp'    => [
				'entityId'            => '',
				'singleSignOnService' => [
					'url'     => '',
					'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
				],
				'x509cert'            => '',
			],
			'security' => [
				'authnRequestsSigned'       => false,
				'wantAssertionsSigned'      => true,
				'wantAssertionsEncrypted'   => false,
				'wantNameIdEncrypted'       => false,
				'wantMessagesSigned'        => false,
				'signatureAlgorithm'        => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
				'digestAlgorithm'           => 'http://www.w3.org/2001/04/xmlenc#sha256',
			],
		];

		if ( $idp ) {
			$settings['idp']['entityId']                          = $idp['entity_id'] ?? '';
			$settings['idp']['singleSignOnService']['url']        = $idp['sso_url'] ?? '';
			$settings['idp']['x509cert']                          = self::clean_cert( $idp['certificate'] ?? '' );
		}

		return $settings;
	}

	/**
	 * Strip PEM headers/footers and whitespace from a certificate string.
	 */
	private static function clean_cert( string $cert ): string {
		$cert = str_replace( [ '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----' ], '', $cert );
		return trim( preg_replace( '/\s+/', '', $cert ) );
	}
}
