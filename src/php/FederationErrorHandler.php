<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shared masked-failure logging for federation flows.
 */
final class FederationErrorHandler {

	public const REFERENCE_QUERY_ARG = 'sso_error_ref';

	/**
	 * Log a masked federation failure and return its correlation ID.
	 *
	 * @param array<string, scalar|null> $context
	 */
	public static function log( string $protocol, string $source, string $detail, array $context = array(), ?\Throwable $exception = null ): string {
		$reference = wp_generate_uuid4();

		$payload = array(
			'reference'      => $reference,
			'protocol'       => sanitize_key( $protocol ),
			'source'         => sanitize_key( $source ),
			'blog_id'        => get_current_blog_id(),
			'request_method' => self::read_server_value( 'REQUEST_METHOD' ),
			'request_uri'    => self::read_server_value( 'REQUEST_URI' ),
			'remote_ip'      => self::read_server_value( 'REMOTE_ADDR' ),
			'detail'         => self::normalize_text( $detail ),
		);

		foreach ( $context as $key => $value ) {
			$normalized_key   = sanitize_key( (string) $key );
			$normalized_value = self::normalize_context_value( $value );

			if ( '' === $normalized_key || null === $normalized_value ) {
				continue;
			}

			$payload[ $normalized_key ] = $normalized_value;
		}

		if ( null !== $exception ) {
			$payload['exception_class']   = self::normalize_text( $exception::class );
			$payload['exception_message'] = self::normalize_text( $exception->getMessage() );

			if ( 0 !== (int) $exception->getCode() ) {
				$payload['exception_code'] = (int) $exception->getCode();
			}
		}

		$payload = array_filter(
			$payload,
			static function ( $value ): bool {
				if ( null === $value ) {
					return false;
				}

				if ( is_string( $value ) ) {
					return '' !== $value;
				}

				return true;
			}
		);

		$encoded = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		if ( false === $encoded ) {
			$encoded = sprintf(
				'reference=%s protocol=%s source=%s blog_id=%d detail=%s',
				$reference,
				$payload['protocol'] ?? '',
				$payload['source'] ?? '',
				(int) ( $payload['blog_id'] ?? 0 ),
				self::normalize_text( $detail )
			);
		}

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		error_log( 'Enterprise IAM – Federation failure: ' . $encoded );

		return $reference;
	}

	/**
	 * Build the masked public login URL with a correlation ID.
	 */
	public static function login_error_url( string $error_code, string $reference = '' ): string {
		$query_args = array(
			'sso_error' => sanitize_key( $error_code ),
		);

		if ( '' !== $reference ) {
			$query_args[ self::REFERENCE_QUERY_ARG ] = sanitize_text_field( $reference );
		}

		return add_query_arg( $query_args, wp_login_url() );
	}

	/**
	 * Normalize a scalar context value for structured logging.
	 */
	private static function normalize_context_value( mixed $value ): string|int|float|bool|null {
		if ( is_bool( $value ) || is_int( $value ) || is_float( $value ) ) {
			return $value;
		}

		if ( null === $value || ! is_scalar( $value ) ) {
			return null;
		}

		$normalized = self::normalize_text( (string) $value );
		return '' === $normalized ? null : $normalized;
	}

	/**
	 * Read and normalize a server value if present.
	 */
	private static function read_server_value( string $key ): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$value = $_SERVER[ $key ] ?? '';
		if ( ! is_string( $value ) ) {
			return '';
		}

		return self::normalize_text( $value );
	}

	/**
	 * Strip control characters from log payload values.
	 */
	private static function normalize_text( string $value ): string {
		$value = trim( $value );
		return (string) preg_replace( '/[\x00-\x1F\x7F]/u', '', $value );
	}
}