<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Starts protocol-specific federation flows with centralized key generation
 * and transient payload persistence.
 */
final class FederationFlowManager {

	private const SAML_TTL_SECONDS = 300;
	private const OIDC_TTL_SECONDS = 600;

	/**
	 * Build and persist a browser-bound SAML flow.
	 *
	 * @param callable(string):array<string, string>|\WP_Error $redirect_builder
	 * @return array<string, string>|\WP_Error
	 */
	public static function start_saml_flow( string $idp_id, int $blog_id, callable $redirect_builder ) {
		$relay_state = self::random_hex( 16 );
		if ( is_wp_error( $relay_state ) ) {
			return $relay_state;
		}

		$redirect = $redirect_builder( $relay_state );
		if ( is_wp_error( $redirect ) ) {
			return $redirect;
		}

		$sso_url    = isset( $redirect['redirect_url'] ) ? (string) $redirect['redirect_url'] : '';
		$request_id = isset( $redirect['request_id'] ) ? (string) $redirect['request_id'] : '';

		if ( '' === $sso_url || '' === $request_id ) {
			return new \WP_Error(
				'ea_federation_flow_saml_invalid',
				'Could not build SAML request correlation data.'
			);
		}

		$issued = FederationFlowGuard::issue(
			'saml',
			$relay_state,
			array(
				'idp_id'     => $idp_id,
				'blog_id'    => $blog_id,
				'request_id' => $request_id,
			),
			self::SAML_TTL_SECONDS
		);

		if ( is_wp_error( $issued ) ) {
			return $issued;
		}

		return array(
			'redirect_url' => $sso_url,
			'flow_key'     => $relay_state,
		);
	}

	/**
	 * Build and persist a browser-bound OIDC flow with PKCE values.
	 *
	 * @return array<string, string>|\WP_Error
	 */
	public static function start_oidc_flow( string $idp_id, int $blog_id ) {
		$state = self::random_hex( 16 );
		if ( is_wp_error( $state ) ) {
			return $state;
		}

		$nonce = self::random_hex( 16 );
		if ( is_wp_error( $nonce ) ) {
			return $nonce;
		}

		$code_verifier = self::base64url_random( 32 );
		if ( is_wp_error( $code_verifier ) ) {
			return $code_verifier;
		}

		$code_challenge = rtrim( strtr( base64_encode( hash( 'sha256', $code_verifier, true ) ), '+/', '-_' ), '=' );

		$issued = FederationFlowGuard::issue(
			'oidc',
			$state,
			array(
				'idp_id'        => $idp_id,
				'blog_id'       => $blog_id,
				'state'         => $state,
				'nonce'         => $nonce,
				'code_verifier' => $code_verifier,
			),
			self::OIDC_TTL_SECONDS
		);

		if ( is_wp_error( $issued ) ) {
			return $issued;
		}

		return array(
			'state'          => $state,
			'nonce'          => $nonce,
			'code_challenge' => $code_challenge,
		);
	}

	/**
	 * @return string|\WP_Error
	 */
	private static function random_hex( int $bytes ) {
		try {
			return bin2hex( random_bytes( $bytes ) );
		} catch ( \Throwable $e ) {
			return new \WP_Error( 'ea_federation_flow_random', 'Federation flow values could not be generated.' );
		}
	}

	/**
	 * @return string|\WP_Error
	 */
	private static function base64url_random( int $bytes ) {
		try {
			return rtrim( strtr( base64_encode( random_bytes( $bytes ) ), '+/', '-_' ), '=' );
		} catch ( \Throwable $e ) {
			return new \WP_Error( 'ea_federation_flow_random', 'Federation flow values could not be generated.' );
		}
	}
}
