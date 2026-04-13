<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * REST API controller for plugin settings.
 *
 * Namespace: enterprise-auth/v1
 * Routes:
 *   GET  /settings       – read current settings
 *   POST /settings       – update settings
 */
final class SettingsController {

	private const NAMESPACE = 'enterprise-auth/v1';
	private const OPTION_KEY = 'enterprise_auth_settings';
	private const NETWORK_DEFAULTS_OPTION_KEY = 'enterprise_auth_network_defaults';
	private const NETWORK_POLICY_OPTION_KEY = 'enterprise_auth_network_policy';
	private const BOOLEAN_KEYS = array( 'lockdown_mode', 'app_passwords', 'require_device_bound_authenticators' );
	private const NETWORK_DEFAULT_KEYS = array( 'lockdown_mode', 'app_passwords', 'require_device_bound_authenticators', 'role_ceiling', 'session_timeout' );

	/**
	 * Register REST routes.
	 */
	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/settings',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_settings' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'update_settings' ),
					'permission_callback' => array( $this, 'check_permission' ),
					'args'                => $this->get_update_args(),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/settings/scim-token',
			array(
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'generate_scim_token' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);
	}

	private const DEFAULTS = array(
		'lockdown_mode'   => true,
		'app_passwords'   => false,
		'require_device_bound_authenticators' => false,
		'role_ceiling'    => 'editor',
		'session_timeout' => 8,
		'deprovision_steward_user_id' => 0,
	);

	private const NETWORK_POLICY_DEFAULTS = array(
		'allow_site_overrides' => array(
			'lockdown_mode' => false,
			'app_passwords' => false,
			'require_device_bound_authenticators' => true,
			'role_ceiling' => false,
			'session_timeout' => true,
		),
		'allow_site_role_mappings' => true,
		'allow_site_scim' => true,
	);

	private const ALLOWED_CEILINGS = array( 'editor', 'author', 'contributor', 'subscriber' );

	/** Allowed SSO session timeout values in hours. */
	private const ALLOWED_TIMEOUTS = array( 1, 2, 4, 8, 12, 24 );

	/**
	 * Only administrators may access these endpoints.
	 * The REST infrastructure automatically verifies the X-WP-Nonce header.
	 */
	public function check_permission( \WP_REST_Request $_request ): bool {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Return current settings.
	 */
	public function get_settings( \WP_REST_Request $_request ): \WP_REST_Response {
		return new \WP_REST_Response( self::read(), 200 );
	}

	/**
	 * Update settings – aggressively sanitize, then persist.
	 */
	public function update_settings( \WP_REST_Request $request ): \WP_REST_Response {
		$previous_effective = self::read();
		$params             = $request->get_json_params();

		if ( ! is_array( $params ) ) {
			$params = array();
		}

		$local_settings = self::read_local_settings();
		$sanitized      = self::sanitize_settings_payload( $params, $local_settings, true );

		if ( ! self::uses_network_settings() ) {
			update_option( self::OPTION_KEY, $sanitized );

			$current_effective = self::read();
			self::sync_device_bound_policy_transition(
				(bool) ( $previous_effective['require_device_bound_authenticators'] ?? self::DEFAULTS['require_device_bound_authenticators'] ),
				(bool) ( $current_effective['require_device_bound_authenticators'] ?? self::DEFAULTS['require_device_bound_authenticators'] )
			);

			return new \WP_REST_Response( $current_effective, 200 );
		}

		$network_defaults = self::read_network_defaults();
		$network_policy   = self::read_network_policy();

		foreach ( self::NETWORK_DEFAULT_KEYS as $key ) {
			if ( ! self::site_can_override( $key, $network_policy ) ) {
				unset( $local_settings[ $key ] );
				continue;
			}

			if ( ! array_key_exists( $key, $params ) ) {
				continue;
			}

			if ( $sanitized[ $key ] === $network_defaults[ $key ] ) {
				unset( $local_settings[ $key ] );
				continue;
			}

			$local_settings[ $key ] = $sanitized[ $key ];
		}

		if ( array_key_exists( 'deprovision_steward_user_id', $params ) ) {
			$local_settings['deprovision_steward_user_id'] = $sanitized['deprovision_steward_user_id'];
		}

		update_option( self::OPTION_KEY, $local_settings );

		$current_effective = self::read();
		self::sync_device_bound_policy_transition(
			(bool) ( $previous_effective['require_device_bound_authenticators'] ?? self::DEFAULTS['require_device_bound_authenticators'] ),
			(bool) ( $current_effective['require_device_bound_authenticators'] ?? self::DEFAULTS['require_device_bound_authenticators'] )
		);

		return new \WP_REST_Response( $current_effective, 200 );
	}

	// ── Public static reader (used by SecurityManager) ──────────────────────

	/**
	 * Read the consolidated settings option.
	 *
	 * @return array<string, mixed>
	 */
	public static function read(): array {
		if ( self::uses_network_settings() ) {
			return self::read_effective_network_settings();
		}

		return self::read_single_site_settings();
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function read_network_defaults(): array {
		$raw = get_site_option( self::NETWORK_DEFAULTS_OPTION_KEY, array() );

		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		$defaults = self::sanitize_settings_payload( $raw, self::DEFAULTS, false );

		return array(
			'lockdown_mode' => (bool) $defaults['lockdown_mode'],
			'app_passwords' => (bool) $defaults['app_passwords'],
			'require_device_bound_authenticators' => (bool) $defaults['require_device_bound_authenticators'],
			'role_ceiling' => (string) $defaults['role_ceiling'],
			'session_timeout' => (int) $defaults['session_timeout'],
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function read_network_policy(): array {
		$raw = get_site_option( self::NETWORK_POLICY_OPTION_KEY, array() );

		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		return self::sanitize_network_policy( $raw );
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function read_network_settings_payload(): array {
		return array(
			'defaults' => self::read_network_defaults(),
			'policy' => self::read_network_policy(),
		);
	}

	/**
	 * @param array<string, mixed> $payload
	 * @return array<string, mixed>
	 */
	public static function update_network_settings_payload( array $payload ): array {
		$previous_site_policies = self::snapshot_effective_device_bound_policy_by_site();

		$defaults_payload = isset( $payload['defaults'] ) && is_array( $payload['defaults'] ) ? $payload['defaults'] : array();
		$policy_payload   = isset( $payload['policy'] ) && is_array( $payload['policy'] ) ? $payload['policy'] : array();

		$defaults = self::sanitize_settings_payload( $defaults_payload, self::read_network_defaults(), false );
		$policy   = self::sanitize_network_policy( $policy_payload );

		update_site_option( self::NETWORK_DEFAULTS_OPTION_KEY, $defaults );
		update_site_option( self::NETWORK_POLICY_OPTION_KEY, $policy );

		$current_site_policies = self::snapshot_effective_device_bound_policy_by_site();
		foreach ( $current_site_policies as $blog_id => $current ) {
			$previous = $previous_site_policies[ $blog_id ] ?? self::DEFAULTS['require_device_bound_authenticators'];
			self::with_blog(
				(int) $blog_id,
				static function () use ( $previous, $current ): void {
					self::sync_device_bound_policy_transition( (bool) $previous, (bool) $current );
				}
			);
		}

		return self::read_network_settings_payload();
	}

	/**
	 * Read the current site's configured deprovision steward user ID.
	 */
	public static function read_deprovision_steward_user_id(): int {
		$candidate = self::read_raw_deprovision_steward_user_id();

		return self::is_valid_steward_user_id( $candidate ) ? $candidate : self::DEFAULTS['deprovision_steward_user_id'];
	}

	/**
	 * Read the raw configured deprovision steward user ID for the current site.
	 */
	public static function read_raw_deprovision_steward_user_id(): int {
		$raw = self::read_local_settings();
		if ( ! isset( $raw['deprovision_steward_user_id'] ) ) {
			return self::DEFAULTS['deprovision_steward_user_id'];
		}

		return (int) $raw['deprovision_steward_user_id'];
	}

	private static function uses_network_settings(): bool {
		return NetworkMode::is_network_mode();
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function read_single_site_settings(): array {
		$local_settings   = self::read_local_settings();
		$steward_user_id  = self::read_deprovision_steward_user_id();
		$scope_meta = array();

		foreach ( self::NETWORK_DEFAULT_KEYS as $key ) {
			$scope_meta[ $key ] = self::build_scope_meta(
				'Site Only',
				'site-only',
				true,
				'This setting is configured on this site only.'
			);
		}

		$scope_meta['deprovision_steward_user_id'] = self::build_scope_meta(
			'Site Only',
			'site-only',
			true,
			'This setting is configured on this site only.'
		);

		return array(
			'lockdown_mode' => (bool) ( $local_settings['lockdown_mode'] ?? self::DEFAULTS['lockdown_mode'] ),
			'app_passwords' => (bool) ( $local_settings['app_passwords'] ?? self::DEFAULTS['app_passwords'] ),
			'require_device_bound_authenticators' => (bool) ( $local_settings['require_device_bound_authenticators'] ?? self::DEFAULTS['require_device_bound_authenticators'] ),
			'role_ceiling' => (string) ( $local_settings['role_ceiling'] ?? self::DEFAULTS['role_ceiling'] ),
			'session_timeout' => (int) ( $local_settings['session_timeout'] ?? self::DEFAULTS['session_timeout'] ),
			'deprovision_steward_user_id' => $steward_user_id,
			'deprovision_steward_options' => self::get_steward_options(),
			'scope_meta' => $scope_meta,
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function read_effective_network_settings(): array {
		$network_defaults = self::read_network_defaults();
		$network_policy   = self::read_network_policy();
		$local_settings   = self::read_local_settings();
		$scope_meta       = array();
		$effective        = array();

		foreach ( self::NETWORK_DEFAULT_KEYS as $key ) {
			$can_override = self::site_can_override( $key, $network_policy );
			$has_override = $can_override && array_key_exists( $key, $local_settings );

			$effective[ $key ] = $has_override ? $local_settings[ $key ] : $network_defaults[ $key ];

			if ( $has_override ) {
				$scope_meta[ $key ] = self::build_scope_meta(
					'Site Override',
					'override',
					true,
					'This site overrides the current network default.'
				);
				continue;
			}

			if ( $can_override ) {
				$scope_meta[ $key ] = self::build_scope_meta(
					'Inherited',
					'inherited',
					true,
					'This site is currently using the network default. Saving a new value will create a site override.'
				);
				continue;
			}

			$scope_meta[ $key ] = self::build_scope_meta(
				'Locked by Network',
				'locked',
				false,
				'This setting is managed in Network Admin and cannot be overridden on this site.'
			);
		}

		$scope_meta['deprovision_steward_user_id'] = self::build_scope_meta(
			'Site Only',
			'site-only',
			true,
			'This setting remains site-scoped even when network defaults are enabled.'
		);

		$effective['deprovision_steward_user_id'] = self::read_deprovision_steward_user_id();
		$effective['deprovision_steward_options'] = self::get_steward_options();
		$effective['scope_meta'] = $scope_meta;

		return $effective;
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function read_local_settings(): array {
		$raw = get_option( self::OPTION_KEY, array() );

		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		$local = array();
		foreach ( self::BOOLEAN_KEYS as $key ) {
			if ( array_key_exists( $key, $raw ) ) {
				$local[ $key ] = (bool) $raw[ $key ];
			}
		}

		if ( isset( $raw['role_ceiling'] ) && in_array( $raw['role_ceiling'], self::ALLOWED_CEILINGS, true ) ) {
			$local['role_ceiling'] = $raw['role_ceiling'];
		}

		if ( isset( $raw['session_timeout'] ) && in_array( (int) $raw['session_timeout'], self::ALLOWED_TIMEOUTS, true ) ) {
			$local['session_timeout'] = (int) $raw['session_timeout'];
		}

		if ( array_key_exists( 'deprovision_steward_user_id', $raw ) ) {
			$candidate = absint( $raw['deprovision_steward_user_id'] );
			$local['deprovision_steward_user_id'] = self::is_valid_steward_user_id( $candidate ) ? $candidate : 0;
		}

		return $local;
	}

	/**
	 * @param array<string, mixed> $params
	 * @param array<string, mixed> $fallback
	 * @return array<string, mixed>
	 */
	private static function sanitize_settings_payload( array $params, array $fallback, bool $include_deprovision ): array {
		$sanitized = array();

		foreach ( self::BOOLEAN_KEYS as $key ) {
			$sanitized[ $key ] = array_key_exists( $key, $params )
				? rest_sanitize_boolean( $params[ $key ] )
				: (bool) ( $fallback[ $key ] ?? self::DEFAULTS[ $key ] );
		}

		$sanitized['role_ceiling'] = isset( $params['role_ceiling'] ) && in_array( $params['role_ceiling'], self::ALLOWED_CEILINGS, true )
			? $params['role_ceiling']
			: (string) ( $fallback['role_ceiling'] ?? self::DEFAULTS['role_ceiling'] );

		$sanitized['session_timeout'] = isset( $params['session_timeout'] ) && in_array( (int) $params['session_timeout'], self::ALLOWED_TIMEOUTS, true )
			? (int) $params['session_timeout']
			: (int) ( $fallback['session_timeout'] ?? self::DEFAULTS['session_timeout'] );

		if ( $include_deprovision ) {
			if ( array_key_exists( 'deprovision_steward_user_id', $params ) ) {
				$candidate = absint( $params['deprovision_steward_user_id'] );
				$sanitized['deprovision_steward_user_id'] = self::is_valid_steward_user_id( $candidate ) ? $candidate : 0;
			} else {
				$sanitized['deprovision_steward_user_id'] = (int) ( $fallback['deprovision_steward_user_id'] ?? self::DEFAULTS['deprovision_steward_user_id'] );
			}
		}

		return $sanitized;
	}

	/**
	 * @param array<string, mixed> $policy
	 * @return array<string, mixed>
	 */
	private static function sanitize_network_policy( array $policy ): array {
		$allow_site_overrides = isset( $policy['allow_site_overrides'] ) && is_array( $policy['allow_site_overrides'] )
			? $policy['allow_site_overrides']
			: array();

		$sanitized_allow_site_overrides = array();
		foreach ( self::NETWORK_POLICY_DEFAULTS['allow_site_overrides'] as $key => $default ) {
			$sanitized_allow_site_overrides[ $key ] = array_key_exists( $key, $allow_site_overrides )
				? rest_sanitize_boolean( $allow_site_overrides[ $key ] )
				: (bool) $default;
		}

		return array(
			'allow_site_overrides' => $sanitized_allow_site_overrides,
			'allow_site_role_mappings' => array_key_exists( 'allow_site_role_mappings', $policy )
				? rest_sanitize_boolean( $policy['allow_site_role_mappings'] )
				: (bool) self::NETWORK_POLICY_DEFAULTS['allow_site_role_mappings'],
			'allow_site_scim' => array_key_exists( 'allow_site_scim', $policy )
				? rest_sanitize_boolean( $policy['allow_site_scim'] )
				: (bool) self::NETWORK_POLICY_DEFAULTS['allow_site_scim'],
		);
	}

	/**
	 * @param array<string, mixed> $policy
	 */
	private static function site_can_override( string $key, array $policy ): bool {
		return ! empty( $policy['allow_site_overrides'][ $key ] );
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function build_scope_meta( string $label, string $tone, bool $editable, string $description ): array {
		return array(
			'label' => $label,
			'tone' => $tone,
			'editable' => $editable,
			'description' => $description,
		);
	}

	private static function sync_device_bound_policy_transition( bool $previous, bool $current ): void {
		PasskeyPolicy::sync_device_bound_policy( $previous, $current );
	}

	/**
	 * @return array<int, bool>
	 */
	private static function snapshot_effective_device_bound_policy_by_site(): array {
		if ( ! is_multisite() ) {
			return array(
				get_current_blog_id() => (bool) ( self::read()['require_device_bound_authenticators'] ?? self::DEFAULTS['require_device_bound_authenticators'] ),
			);
		}

		$results = array();
		foreach ( get_sites( array( 'number' => 0 ) ) as $site ) {
			$blog_id = (int) $site->blog_id;
			$results[ $blog_id ] = (bool) self::with_blog(
				$blog_id,
				static fn(): bool => (bool) ( self::read()['require_device_bound_authenticators'] ?? self::DEFAULTS['require_device_bound_authenticators'] )
			);
		}

		return $results;
	}

	private static function with_blog( int $blog_id, callable $callback ): mixed {
		if ( ! is_multisite() || $blog_id <= 0 || get_current_blog_id() === $blog_id ) {
			return $callback();
		}

		switch_to_blog( $blog_id );
		try {
			return $callback();
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Schema for the POST /settings arguments.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private function get_update_args(): array {
		return array(
			'lockdown_mode' => array(
				'type'              => 'boolean',
				'required'          => false,
				'sanitize_callback' => 'rest_sanitize_boolean',
			),
			'app_passwords' => array(
				'type'              => 'boolean',
				'required'          => false,
				'sanitize_callback' => 'rest_sanitize_boolean',
			),
			'require_device_bound_authenticators' => array(
				'type'              => 'boolean',
				'required'          => false,
				'sanitize_callback' => 'rest_sanitize_boolean',
			),
			'role_ceiling'    => array(
				'type'              => 'string',
				'required'          => false,
				'enum'              => array( 'editor', 'author', 'contributor', 'subscriber' ),
				'sanitize_callback' => 'sanitize_text_field',
			),
			'session_timeout' => array(
				'type'              => 'integer',
				'required'          => false,
				'enum'              => array( 1, 2, 4, 8, 12, 24 ),
				'sanitize_callback' => 'absint',
			),
			'deprovision_steward_user_id' => array(
				'type'              => 'integer',
				'required'          => false,
				'sanitize_callback' => 'absint',
			),
		);
	}

	/**
	 * Check whether a user is eligible to act as the site's content steward.
	 */
	private static function is_valid_steward_user_id( int $user_id ): bool {
		if ( $user_id <= 0 || 1 === $user_id || is_super_admin( $user_id ) ) {
			return false;
		}

		$user = get_userdata( $user_id );
		if ( ! ( $user instanceof \WP_User ) ) {
			return false;
		}

		if ( is_multisite() && ! is_user_member_of_blog( $user_id, get_current_blog_id() ) ) {
			return false;
		}

		return user_can( $user, 'edit_posts' );
	}

	/**
	 * Return the current site's eligible content-steward options.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function get_steward_options(): array {
		$args = array(
			'fields'  => 'all',
			'orderby' => 'display_name',
			'order'   => 'ASC',
		);

		if ( is_multisite() ) {
			$args['blog_id'] = get_current_blog_id();
		}

		$options = array();
		foreach ( get_users( $args ) as $user ) {
			if ( ! ( $user instanceof \WP_User ) || ! self::is_valid_steward_user_id( $user->ID ) ) {
				continue;
			}

			$options[] = array(
				'id'    => $user->ID,
				'label' => sprintf( '%s (%s, ID %d)', $user->display_name ?: $user->user_login, $user->user_email ?: $user->user_login, $user->ID ),
			);
		}

		return $options;
	}

	/**
	 * Format the configured steward for the admin UI.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function format_steward_user( int $user_id ): ?array {
		if ( ! self::is_valid_steward_user_id( $user_id ) ) {
			return null;
		}

		$user = get_userdata( $user_id );
		if ( ! ( $user instanceof \WP_User ) ) {
			return null;
		}

		return array(
			'id'           => $user->ID,
			'user_login'   => $user->user_login,
			'display_name' => $user->display_name,
			'user_email'   => $user->user_email,
		);
	}

	// ── SCIM Token Generation ───────────────────────────────────────────────

	private const SCIM_TOKEN_OPTION = 'enterprise_iam_scim_token';

	/**
	 * Generate a new SCIM Bearer token.
	 *
	 * Creates a cryptographically secure 40-character token, stores only
	 * the bcrypt hash in wp_options, and returns the plaintext exactly
	 * once to the admin UI. The plaintext is never persisted.
	 */
	public function generate_scim_token( \WP_REST_Request $_request ): \WP_REST_Response {
		$plaintext = wp_generate_password( 40, false );
		$hash      = wp_hash_password( $plaintext );

		update_option( self::SCIM_TOKEN_OPTION, $hash );

		return new \WP_REST_Response(
			array(
				'token'    => $plaintext,
				'base_url' => rest_url( self::NAMESPACE . '/scim/v2/' ),
			),
			201
		);
	}
}
