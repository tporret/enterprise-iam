<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AuditLogger {

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function events( int $limit = 100 ): array {
		global $wpdb;

		$limit = max( 1, min( 200, $limit ) );
		$table = DatabaseManager::audit_table_name();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, event, source, result, actor_user_id, target_user_id, blog_id, network_id, request_route, request_method, request_ip, request_user_agent, metadata, created_at FROM {$table} ORDER BY created_at DESC, id DESC LIMIT %d",
				$limit
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return array();
		}

		return array_map( array( self::class, 'row_to_event' ), $rows );
	}

	/**
	 * @param array<string, mixed> $context
	 */
	public function record_identity_event( string $event, array $context = array() ): void {
		self::record( $event, $context );
	}

	/**
	 * @param array<string, mixed> $context
	 */
	public static function record( string $event, array $context = array() ): void {
		global $wpdb;

		$event = sanitize_key( $event );
		if ( '' === $event ) {
			return;
		}

		$context = self::sanitize_context( $context );
		$row     = array(
			'event'              => $event,
			'source'             => sanitize_key( (string) ( $context['source'] ?? 'system' ) ),
			'result'             => sanitize_key( (string) ( $context['result'] ?? 'success' ) ),
			'actor_user_id'      => self::nullable_absint( $context['actor_user_id'] ?? get_current_user_id() ),
			'target_user_id'     => self::nullable_absint( $context['target_user_id'] ?? $context['user_id'] ?? null ),
			'blog_id'            => self::nullable_absint( $context['blog_id'] ?? get_current_blog_id() ),
			'network_id'         => self::nullable_absint( $context['network_id'] ?? null ),
			'request_route'      => sanitize_text_field( (string) ( $context['request_route'] ?? '' ) ),
			'request_method'     => strtoupper( sanitize_key( (string) ( $context['request_method'] ?? '' ) ) ),
			'request_ip'         => sanitize_text_field( (string) ( $context['request_ip'] ?? self::request_ip() ) ),
			'request_user_agent' => sanitize_text_field( substr( (string) ( $context['request_user_agent'] ?? self::request_user_agent() ), 0, 255 ) ),
			'metadata'           => wp_json_encode( self::redact_metadata( $context ) ),
			'created_at'         => current_time( 'mysql', true ),
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			DatabaseManager::audit_table_name(),
			$row,
			array( '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * @param array<string, mixed> $context
	 * @return array<string, mixed>
	 */
	private static function sanitize_context( array $context ): array {
		$sanitized = array();

		foreach ( $context as $key => $value ) {
			$sanitized[ sanitize_key( (string) $key ) ] = self::sanitize_value( $value );
		}

		return $sanitized;
	}

	/**
	 * @param array<string, mixed> $row
	 * @return array<string, mixed>
	 */
	private static function row_to_event( array $row ): array {
		$metadata = json_decode( (string) ( $row['metadata'] ?? '{}' ), true );
		if ( ! is_array( $metadata ) ) {
			$metadata = array();
		}

		return array(
			'id'                 => (int) ( $row['id'] ?? 0 ),
			'event'              => (string) ( $row['event'] ?? '' ),
			'source'             => (string) ( $row['source'] ?? '' ),
			'result'             => (string) ( $row['result'] ?? '' ),
			'actor_user_id'      => isset( $row['actor_user_id'] ) ? (int) $row['actor_user_id'] : null,
			'target_user_id'     => isset( $row['target_user_id'] ) ? (int) $row['target_user_id'] : null,
			'blog_id'            => isset( $row['blog_id'] ) ? (int) $row['blog_id'] : null,
			'network_id'         => isset( $row['network_id'] ) ? (int) $row['network_id'] : null,
			'request_route'      => (string) ( $row['request_route'] ?? '' ),
			'request_method'     => (string) ( $row['request_method'] ?? '' ),
			'request_ip'         => (string) ( $row['request_ip'] ?? '' ),
			'request_user_agent' => (string) ( $row['request_user_agent'] ?? '' ),
			'metadata'           => $metadata,
			'created_at'         => (string) ( $row['created_at'] ?? '' ),
		);
	}

	private static function sanitize_value( mixed $value ): mixed {
		if ( is_array( $value ) ) {
			$sanitized = array();
			foreach ( $value as $key => $nested_value ) {
				$sanitized[ is_int( $key ) ? $key : sanitize_key( (string) $key ) ] = self::sanitize_value( $nested_value );
			}

			return $sanitized;
		}

		if ( is_bool( $value ) || is_int( $value ) || is_float( $value ) || null === $value ) {
			return $value;
		}

		return sanitize_text_field( (string) $value );
	}

	private static function nullable_absint( mixed $value ): ?int {
		$integer = absint( $value );
		return $integer > 0 ? $integer : null;
	}

	/**
	 * @param array<string, mixed> $metadata
	 * @return array<string, mixed>
	 */
	private static function redact_metadata( array $metadata ): array {
		$redacted = array();

		foreach ( $metadata as $key => $value ) {
			if ( self::is_sensitive_key( (string) $key ) ) {
				$redacted[ $key ] = '[redacted]';
				continue;
			}

			$redacted[ $key ] = is_array( $value ) ? self::redact_metadata( $value ) : $value;
		}

		return $redacted;
	}

	private static function is_sensitive_key( string $key ): bool {
		return 1 === preg_match( '/(?:secret|token|password|assertion|credential_id|public_key|private_key|client_secret)/i', $key );
	}

	private static function request_ip(): string {
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$parts = explode( ',', sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
			return sanitize_text_field( trim( $parts[0] ) );
		}

		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REMOTE_ADDR'] ) ) : '';
	}

	private static function request_user_agent(): string {
		return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( substr( wp_unslash( (string) $_SERVER['HTTP_USER_AGENT'] ), 0, 255 ) ) : '';
	}
}