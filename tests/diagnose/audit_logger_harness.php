<?php

declare( strict_types=1 );

define( 'ABSPATH', __DIR__ . '/../../' );
define( 'ARRAY_A', 'ARRAY_A' );

$GLOBALS['ea_user_id'] = 42;
$GLOBALS['ea_blog_id'] = 9;
$GLOBALS['ea_audit_rows'] = array();

class EA_Audit_Logger_WPDB {
	public string $prefix = 'wp_';

	public function insert( string $table, array $data, array $_format ): bool {
		$GLOBALS['ea_audit_rows'][] = array(
			'table' => $table,
			'data'  => $data,
		);
		return true;
	}

	public function prepare( string $query, mixed ...$args ): string {
		return vsprintf( str_replace( '%d', '%d', $query ), $args );
	}

	public function get_results( string $_query, string $_output ): array {
		return array_map(
			static function ( array $row, int $index ): array {
				return array_merge(
					array( 'id' => $index + 1 ),
					$row['data']
				);
			},
			$GLOBALS['ea_audit_rows'],
			array_keys( $GLOBALS['ea_audit_rows'] )
		);
	}
}

$GLOBALS['wpdb'] = new EA_Audit_Logger_WPDB();

function sanitize_key( string $key ): string {
	return strtolower( preg_replace( '/[^a-zA-Z0-9_\-]/', '', $key ) ?? '' );
}

function sanitize_text_field( string $text ): string {
	return trim( strip_tags( $text ) );
}

function absint( mixed $value ): int {
	return abs( (int) $value );
}

function wp_json_encode( mixed $value ): string {
	return json_encode( $value );
}

function wp_unslash( mixed $value ): mixed {
	return $value;
}

function current_time( string $_type, bool $_gmt = false ): string {
	return '2026-05-25 12:00:00';
}

function get_current_user_id(): int {
	return (int) $GLOBALS['ea_user_id'];
}

function get_current_blog_id(): int {
	return (int) $GLOBALS['ea_blog_id'];
}

require_once __DIR__ . '/../../src/php/DatabaseManager.php';
require_once __DIR__ . '/../../src/php/AuditLogger.php';

$assert = static function ( bool $condition, string $message ): void {
	if ( ! $condition ) {
		fwrite( STDERR, "FAIL: {$message}\n" );
		exit( 1 );
	}
};

EnterpriseAuth\Plugin\AuditLogger::record(
	'idp_saved',
	array(
		'source'        => 'rest',
		'result'        => 'success',
		'user_id'       => 55,
		'client_secret' => 'super-secret',
		'nested'        => array(
			'token' => 'plain-token',
		),
	)
);

$assert( 1 === count( $GLOBALS['ea_audit_rows'] ), 'Audit logger should write one row.' );
$row = $GLOBALS['ea_audit_rows'][0]['data'];
$assert( 'wp_enterprise_auth_audit_events' === $GLOBALS['ea_audit_rows'][0]['table'], 'Audit logger should use the audit table.' );
$assert( 'idp_saved' === $row['event'], 'Audit event name should be preserved.' );
$assert( 42 === $row['actor_user_id'], 'Audit actor should default to current user.' );
$assert( 55 === $row['target_user_id'], 'Audit target should default from user_id context.' );
$assert( 9 === $row['blog_id'], 'Audit blog should default to the current blog.' );

$metadata = json_decode( $row['metadata'], true );
$assert( '[redacted]' === $metadata['client_secret'], 'Audit metadata should redact client secrets.' );
$assert( '[redacted]' === $metadata['nested']['token'], 'Audit metadata should redact nested tokens.' );

$events = EnterpriseAuth\Plugin\AuditLogger::events( 20 );
$assert( 1 === count( $events ), 'Audit events should be readable.' );
$assert( '[redacted]' === $events[0]['metadata']['client_secret'], 'Readable audit events should keep redacted metadata.' );

echo "PASS: Audit logger stores readable redacted events.\n";