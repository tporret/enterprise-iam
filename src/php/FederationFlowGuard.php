<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Ephemeral federation flow storage with browser binding.
 */
final class FederationFlowGuard {

	/**
	 * Persist a short-lived federation flow and bind it to the initiating browser.
	 *
	 * @param array<string, mixed> $payload
	 * @return true|\WP_Error
	 */
	public static function issue( string $protocol, string $flow_key, array $payload, int $ttl ) {
		$protocol = sanitize_key( $protocol );
		$flow_key = sanitize_text_field( $flow_key );

		if ( '' === $protocol || '' === $flow_key ) {
			return new \WP_Error( 'ea_federation_flow_invalid', 'Federation flow key was invalid.' );
		}

		if ( 'saml' === $protocol && ! is_ssl() ) {
			return new \WP_Error(
				'ea_federation_flow_https_required',
				'SAML SSO requires HTTPS to enforce browser-bound request correlation.'
			);
		}

		try {
			$payload['browser_binding'] = bin2hex( random_bytes( 32 ) );
		} catch ( \Throwable $e ) {
			return new \WP_Error( 'ea_federation_flow_random', 'Federation flow binding could not be generated.' );
		}

		if ( ! isset( $payload['blog_id'] ) ) {
			$payload['blog_id'] = get_current_blog_id();
		}

		$encoded = wp_json_encode( $payload );
		if ( false === $encoded ) {
			return new \WP_Error( 'ea_federation_flow_encode', 'Federation flow state could not be encoded.' );
		}

		if ( ! set_transient( self::transient_key( $protocol, $flow_key ), $encoded, max( 1, $ttl ) ) ) {
			return new \WP_Error( 'ea_federation_flow_store', 'Federation flow state could not be persisted.' );
		}

		if ( ! self::set_binding_cookie( $protocol, $flow_key, (string) $payload['browser_binding'], $ttl ) ) {
			delete_transient( self::transient_key( $protocol, $flow_key ) );

			return new \WP_Error( 'ea_federation_flow_cookie', 'Federation flow cookie could not be set.' );
		}

		return true;
	}

	/**
	 * Consume a federation flow and verify that it returns from the initiating browser.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function consume( string $protocol, string $flow_key ) {
		$protocol = sanitize_key( $protocol );
		$flow_key = sanitize_text_field( $flow_key );

		if ( '' === $protocol || '' === $flow_key ) {
			return new \WP_Error( 'ea_federation_flow_invalid', 'Federation flow key was invalid.' );
		}

		$transient_key = self::transient_key( $protocol, $flow_key );
		$raw           = OneTimeTransient::consume( $transient_key );

		$cookie_value = self::read_binding_cookie( $protocol, $flow_key );
		self::clear_binding_cookie( $protocol, $flow_key );

		if ( false === $raw || null === $raw ) {
			return new \WP_Error( 'ea_federation_flow_missing', 'Federation flow state was missing or expired.' );
		}

		$data = json_decode( (string) $raw, true );
		if ( ! is_array( $data ) ) {
			return new \WP_Error( 'ea_federation_flow_invalid_payload', 'Federation flow state was malformed.' );
		}

		$stored_binding = isset( $data['browser_binding'] ) && is_string( $data['browser_binding'] )
			? $data['browser_binding']
			: '';
		unset( $data['browser_binding'] );

		if ( isset( $data['blog_id'] ) && (int) $data['blog_id'] !== get_current_blog_id() ) {
			return new \WP_Error( 'ea_federation_flow_blog_mismatch', 'Federation flow did not belong to the current site.' );
		}

		if ( '' === $stored_binding || '' === $cookie_value || ! hash_equals( $stored_binding, $cookie_value ) ) {
			return new \WP_Error(
				'ea_federation_flow_browser_mismatch',
				'Federation flow could not be bound to the initiating browser.'
			);
		}

		return $data;
	}

	private static function transient_key( string $protocol, string $flow_key ): string {
		return 'ea_fed_' . $protocol . '_' . get_current_blog_id() . '_' . $flow_key;
	}

	private static function cookie_name( string $protocol, string $flow_key ): string {
		return 'ea_fed_' . $protocol . '_' . substr( hash( 'sha256', $flow_key ), 0, 32 );
	}

	private static function set_binding_cookie( string $protocol, string $flow_key, string $binding, int $ttl ): bool {
		if ( headers_sent() ) {
			return false;
		}

		$options = array(
			'expires'  => time() + max( 1, $ttl ),
			'path'     => self::cookie_path(),
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => self::cookie_samesite( $protocol ),
		);

		if ( '' !== COOKIE_DOMAIN ) {
			$options['domain'] = COOKIE_DOMAIN;
		}

		return setcookie( self::cookie_name( $protocol, $flow_key ), $binding, $options );
	}

	private static function clear_binding_cookie( string $protocol, string $flow_key ): void {
		if ( headers_sent() ) {
			return;
		}

		$options = array(
			'expires'  => time() - YEAR_IN_SECONDS,
			'path'     => self::cookie_path(),
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => self::cookie_samesite( $protocol ),
		);

		if ( '' !== COOKIE_DOMAIN ) {
			$options['domain'] = COOKIE_DOMAIN;
		}

		setcookie( self::cookie_name( $protocol, $flow_key ), ' ', $options );
	}

	private static function read_binding_cookie( string $protocol, string $flow_key ): string {
		$cookie_name = self::cookie_name( $protocol, $flow_key );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$value = $_COOKIE[ $cookie_name ] ?? '';
		if ( ! is_string( $value ) ) {
			return '';
		}

		return sanitize_text_field( $value );
	}

	private static function cookie_path(): string {
		return '' !== COOKIEPATH ? COOKIEPATH : '/';
	}

	private static function cookie_samesite( string $protocol ): string {
		return 'saml' === $protocol ? 'None' : 'Lax';
	}
}