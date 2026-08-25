<?php

declare( strict_types=1 );

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/../../' );
define( 'ENTERPRISE_AUTH_FILE', __DIR__ . '/../../enterprise-iam.php' );

$GLOBALS['ea_multisite'] = false;
$GLOBALS['ea_network_active'] = false;
$GLOBALS['ea_options'] = array(
	'enterprise_auth_idps' => array(
		array(
			'id'           => 'idp-1',
			'role_mapping' => array(
				'staff' => 'author',
			),
			'enabled'      => true,
		),
	),
	'enterprise_auth_settings' => array(
		'role_ceiling' => 'editor',
	),
);
$GLOBALS['ea_site_options'] = array(
	'enterprise_auth_network_policy' => array(
		'allow_site_scim' => false,
	),
);
$GLOBALS['ea_users'] = array();

class WP_Error {
	public function __construct( private string $code, private string $message, private mixed $data = null ) {}

	public function get_error_code(): string {
		return $this->code;
	}

	public function get_error_message(): string {
		return $this->message;
	}

	public function get_error_data( string $_code = '' ): mixed {
		return $this->data;
	}
}

class WP_User {
	public int $ID;
	/** @var string[] */
	public array $roles;

	/**
	 * @param string[] $roles
	 */
	public function __construct( int $id, array $roles ) {
		$this->ID    = $id;
		$this->roles = $roles;
	}

	public function set_role( string $role ): void {
		$this->roles = '' === $role ? array() : array( $role );
	}
}

class WP_REST_Request {
	public function get_route(): string {
		return '/enterprise-auth/v1/scim/v2/Users';
	}

	public function get_header( string $_name ): string {
		return '';
	}
}

function is_wp_error( mixed $value ): bool {
	return $value instanceof WP_Error;
}

function sanitize_text_field( mixed $text ): string {
	return trim( strip_tags( (string) $text ) );
}

function sanitize_key( string $key ): string {
	return strtolower( preg_replace( '/[^a-zA-Z0-9_\-]/', '', $key ) ?? '' );
}

function sanitize_email( string $email ): string {
	return strtolower( trim( $email ) );
}

function is_email( string $email ): bool {
	return false !== filter_var( $email, FILTER_VALIDATE_EMAIL );
}

function rest_sanitize_boolean( mixed $value ): bool {
	return filter_var( $value, FILTER_VALIDATE_BOOLEAN );
}

function is_multisite(): bool {
	return (bool) $GLOBALS['ea_multisite'];
}

function is_plugin_active_for_network( string $_plugin ): bool {
	return (bool) $GLOBALS['ea_network_active'];
}

function plugin_basename( string $file ): string {
	return basename( $file );
}

function get_current_blog_id(): int {
	return 1;
}

function get_option( string $key, mixed $default = false ): mixed {
	return $GLOBALS['ea_options'][ $key ] ?? $default;
}

function get_site_option( string $key, mixed $default = false ): mixed {
	return $GLOBALS['ea_site_options'][ $key ] ?? $default;
}

function get_user_meta( int $user_id, string $key, bool $_single = false ): mixed {
	return $GLOBALS['ea_user_meta'][ $user_id ][ $key ] ?? '';
}

function get_user_by( string $field, mixed $value ): mixed {
	return 'id' === $field ? ( $GLOBALS['ea_users'][ (int) $value ] ?? false ) : false;
}

function get_users( array $_args = array() ): array {
	return array();
}

function get_role( string $role ): ?object {
	$roles = array(
		'administrator' => array( 'manage_options' => true ),
		'editor'        => array( 'edit_posts' => true ),
		'author'        => array( 'edit_posts' => true ),
		'subscriber'    => array( 'read' => true ),
	);

	return isset( $roles[ $role ] ) ? (object) array( 'capabilities' => $roles[ $role ] ) : null;
}

require_once __DIR__ . '/../../src/php/SiteMetaKeys.php';
require_once __DIR__ . '/../../src/php/SettingsSourceInterface.php';
require_once __DIR__ . '/../../src/php/SiteSettingsSourceAdapter.php';
require_once __DIR__ . '/../../src/php/NetworkSettingsSourceAdapter.php';
require_once __DIR__ . '/../../src/php/EffectiveSettingsResolver.php';
require_once __DIR__ . '/../../src/php/SettingsController.php';
require_once __DIR__ . '/../../src/php/IdpRepositoryInterface.php';
require_once __DIR__ . '/../../src/php/SiteIdpAdapter.php';
require_once __DIR__ . '/../../src/php/NetworkIdpAdapter.php';
require_once __DIR__ . '/../../src/php/IdpRepositoryManager.php';
require_once __DIR__ . '/../../src/php/NetworkMode.php';
require_once __DIR__ . '/../../src/php/NetworkIdpManager.php';
require_once __DIR__ . '/../../src/php/CurrentSiteIdpManager.php';
require_once __DIR__ . '/../../src/php/UserIdentityRepository.php';
require_once __DIR__ . '/../../src/php/EnterpriseProvisioning.php';
require_once __DIR__ . '/../../src/php/Controllers/ScimController.php';

$assert = static function ( bool $condition, string $message ): void {
	if ( ! $condition ) {
		fwrite( STDERR, "FAIL: {$message}\n" );
		exit( 1 );
	}
};

$local_user = new WP_User( 10, array( 'subscriber' ) );
$scim_user  = new WP_User( 11, array( 'subscriber' ) );
$GLOBALS['ea_users'] = array(
	10 => $local_user,
	11 => $scim_user,
);
$GLOBALS['ea_user_meta'] = array(
	11 => array(
		EnterpriseAuth\Plugin\SiteMetaKeys::key( EnterpriseAuth\Plugin\SiteMetaKeys::SCIM_ID ) => 'scim-11',
	),
);

$reflection = new ReflectionClass( EnterpriseAuth\Plugin\Controllers\ScimController::class );
$apply_group = $reflection->getMethod( 'apply_group_to_members' );
$apply_group->setAccessible( true );
$apply_group->invoke( null, 'staff', array( array( 'value' => 10 ), array( 'value' => 11 ) ) );

$assert( array( 'subscriber' ) === $local_user->roles, 'SCIM group sync must not mutate local accounts.' );
$assert( array( 'author' ) === $scim_user->roles, 'SCIM group sync should still mutate SCIM-managed accounts.' );

$GLOBALS['ea_multisite'] = true;
$GLOBALS['ea_network_active'] = true;

$controller = new EnterpriseAuth\Plugin\Controllers\ScimController();
$auth       = $controller->authenticate_scim( new WP_REST_Request() );

$assert( $auth instanceof WP_Error, 'Disabled site SCIM policy should reject SCIM auth.' );
$assert( 'rest_forbidden' === $auth->get_error_code(), 'Disabled site SCIM policy should return a forbidden error.' );
$assert( 403 === ( $auth->get_error_data()['status'] ?? 0 ), 'Disabled site SCIM policy should return HTTP 403.' );

$missing_subject = EnterpriseAuth\Plugin\EnterpriseProvisioning::provision_and_login(
	array( 'id' => 'idp-1' ),
	array(
		'email'          => 'person@example.test',
		'idp_uid'        => '',
		'email_verified' => true,
	)
);

$assert( $missing_subject instanceof WP_Error, 'SSO provisioning must reject missing immutable subjects.' );

echo "PASS: SCIM provisioning guards block local role mutation, disabled policy access, and subjectless SSO.\n";