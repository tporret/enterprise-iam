<?php

declare( strict_types=1 );

define( 'ABSPATH', __DIR__ . '/../../' );

$GLOBALS['ea_logged_in'] = false;
$GLOBALS['ea_caps']      = array();

function is_user_logged_in(): bool {
	return (bool) $GLOBALS['ea_logged_in'];
}

function current_user_can( string $capability ): bool {
	return ! empty( $GLOBALS['ea_caps'][ $capability ] );
}

require_once __DIR__ . '/../../src/php/Controllers/PasskeyRegistrationController.php';

$reflection = new ReflectionClass( EnterpriseAuth\Plugin\Controllers\PasskeyRegistrationController::class );
/** @var EnterpriseAuth\Plugin\Controllers\PasskeyRegistrationController $controller */
$controller = $reflection->newInstanceWithoutConstructor();

$assert = static function ( bool $condition, string $message ): void {
	if ( ! $condition ) {
		fwrite( STDERR, "FAIL: {$message}\n" );
		exit( 1 );
	}
};

$GLOBALS['ea_logged_in'] = false;
$GLOBALS['ea_caps']      = array( 'read' => true );
$assert( false === $controller->check_permission(), 'Logged-out users must not register passkeys.' );

$GLOBALS['ea_logged_in'] = true;
$GLOBALS['ea_caps']      = array();
$assert( false === $controller->check_permission(), 'Users without read capability must not register passkeys.' );

$GLOBALS['ea_logged_in'] = true;
$GLOBALS['ea_caps']      = array( 'read' => true );
$assert( true === $controller->check_permission(), 'Logged-in users with read capability should self-enroll passkeys.' );

echo "PASS: Passkey self-enrollment permission allows current logged-in users only.\n";