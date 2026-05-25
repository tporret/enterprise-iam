<?php

declare( strict_types=1 );

define( 'ABSPATH', __DIR__ . '/../../' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'ARRAY_A', 'ARRAY_A' );

$GLOBALS['ea_logged_in'] = true;
$GLOBALS['ea_user_id']   = 7;
$GLOBALS['ea_transients'] = array();
$GLOBALS['ea_audit_rows'] = array();

class EA_Audit_WPDB {
	public string $prefix = 'wp_';

	public function insert( string $table, array $data, array $_format ): bool {
		$GLOBALS['ea_audit_rows'][] = array(
			'table' => $table,
			'data'  => $data,
		);
		return true;
	}
}

$GLOBALS['wpdb'] = new EA_Audit_WPDB();

class WP_REST_Server {}

class WP_REST_Response {
	private array $data;
	private int $status;

	public function __construct( array $data, int $status ) {
		$this->data   = $data;
		$this->status = $status;
	}

	public function get_status(): int {
		return $this->status;
	}

	public function get_data(): array {
		return $this->data;
	}
}

class WP_REST_Request {
	public function __construct( private string $method, private string $route ) {}

	public function get_method(): string {
		return $this->method;
	}

	public function get_route(): string {
		return $this->route;
	}
}

function __( string $text, string $_domain = '' ): string {
	return $text;
}

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

function is_user_logged_in(): bool {
	return (bool) $GLOBALS['ea_logged_in'];
}

function get_current_user_id(): int {
	return (int) $GLOBALS['ea_user_id'];
}

function get_transient( string $key ): mixed {
	return $GLOBALS['ea_transients'][ $key ] ?? false;
}

function set_transient( string $key, mixed $value, int $_expiration ): bool {
	$GLOBALS['ea_transients'][ $key ] = $value;
	return true;
}

function is_multisite(): bool {
	return false;
}

function get_current_blog_id(): int {
	return 3;
}

require_once __DIR__ . '/../../src/php/DatabaseManager.php';
require_once __DIR__ . '/../../src/php/AuditLogger.php';
require_once __DIR__ . '/../../src/php/PasskeyStepUp.php';
require_once __DIR__ . '/../../src/php/Core.php';

$core   = new EnterpriseAuth\Plugin\Core();
$server = new WP_REST_Server();

$assert = static function ( bool $condition, string $message ): void {
	if ( ! $condition ) {
		fwrite( STDERR, "FAIL: {$message}\n" );
		exit( 1 );
	}
};

$read_request = new WP_REST_Request( 'GET', '/enterprise-auth/v1/settings' );
$assert( null === $core->enforce_high_risk_rest_step_up( null, $server, $read_request ), 'Read requests should not require step-up.' );

$mutation_request = new WP_REST_Request( 'POST', '/enterprise-auth/v1/settings' );
$blocked          = $core->enforce_high_risk_rest_step_up( null, $server, $mutation_request );
$assert( $blocked instanceof WP_REST_Response, 'High-risk settings mutation should be blocked before step-up.' );
$assert( 403 === $blocked->get_status(), 'Blocked mutation should return 403.' );
$assert( 'passkey_step_up_required' === $blocked->get_data()['code'], 'Blocked mutation should identify step-up requirement.' );
$assert( 1 === count( $GLOBALS['ea_audit_rows'] ), 'Blocked mutation should be audited.' );
$assert( 'passkey_step_up_required' === $GLOBALS['ea_audit_rows'][0]['data']['event'], 'Audit event should identify the step-up requirement.' );
$assert( '/enterprise-auth/v1/settings' === $GLOBALS['ea_audit_rows'][0]['data']['request_route'], 'Audit event should include the protected route.' );

EnterpriseAuth\Plugin\PasskeyStepUp::mark_verified( 7 );
$assert( null === $core->enforce_high_risk_rest_step_up( null, $server, $mutation_request ), 'Verified users should continue high-risk mutations.' );

$network_delete = new WP_REST_Request( 'DELETE', '/enterprise-auth/v1/network/idps/01234567-89ab-cdef-0123-456789abcdef' );
$assert( null === $core->enforce_high_risk_rest_step_up( null, $server, $network_delete ), 'Verified users should continue protected network deletes.' );

echo "PASS: Passkey step-up guard protects high-risk REST mutations.\n";