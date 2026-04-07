<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\SamlSettingsFactory;

/**
 * Serves the SP Metadata XML that enterprise IdPs (Okta, Entra ID) need
 * to configure their side of the federation trust.
 *
 * Route: GET /enterprise-auth/v1/saml/metadata
 */
final class SamlMetadataController {

	private const NAMESPACE = 'enterprise-auth/v1';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/saml/metadata',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'metadata' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Generate and return SP metadata XML.
	 */
	public function metadata( \WP_REST_Request $_request ): \WP_REST_Response {
		try {
			$settings = new \OneLogin\Saml2\Settings( SamlSettingsFactory::build(), true );
			$metadata = $settings->getSPMetadata();
			$errors   = $settings->validateMetadata( $metadata );

			if ( ! empty( $errors ) ) {
				return new \WP_REST_Response(
					array( 'error' => 'Metadata validation failed: ' . implode( ', ', $errors ) ),
					500
				);
			}

			// Return raw XML with correct content type.
			$response = new \WP_REST_Response( null, 200 );
			$response->header( 'Content-Type', 'application/samlmetadata+xml; charset=utf-8' );

			// We need to output the XML directly and exit since WP REST framework
			// always JSON-encodes the response body.
			add_filter(
				'rest_pre_serve_request',
				static function ( $_served ) use ( $metadata ) {
					echo $metadata; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					return true;
				}
			);

			return $response;
		} catch ( \Throwable $e ) {
			return new \WP_REST_Response(
				array( 'error' => 'Failed to generate SP metadata: ' . $e->getMessage() ),
				500
			);
		}
	}
}
