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

	private const OPTION_KEY = 'enterprise_auth_settings';

	private const DEFAULTS = array(
		'lockdown_mode'   => true,
		'app_passwords'   => false,
		'role_ceiling'    => 'editor',
		'session_timeout' => 8,
		'deprovision_steward_user_id' => 0,
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
		$current = self::read();
		$params  = $request->get_json_params();

		// Boolean settings.
		$sanitized = array();
		foreach ( array( 'lockdown_mode', 'app_passwords' ) as $key ) {
			$sanitized[ $key ] = isset( $params[ $key ] )
				? rest_sanitize_boolean( $params[ $key ] )
				: $current[ $key ];
		}

		// Role ceiling — must be one of the allowed values.
		if ( isset( $params['role_ceiling'] ) && in_array( $params['role_ceiling'], self::ALLOWED_CEILINGS, true ) ) {
			$sanitized['role_ceiling'] = $params['role_ceiling'];
		} else {
			$sanitized['role_ceiling'] = $current['role_ceiling'];
		}

		// SSO session timeout — must be one of the allowed hour values.
		if ( isset( $params['session_timeout'] ) && in_array( (int) $params['session_timeout'], self::ALLOWED_TIMEOUTS, true ) ) {
			$sanitized['session_timeout'] = (int) $params['session_timeout'];
		} else {
			$sanitized['session_timeout'] = $current['session_timeout'];
		}

		if ( isset( $params['deprovision_steward_user_id'] ) ) {
			$candidate = absint( $params['deprovision_steward_user_id'] );
			$sanitized['deprovision_steward_user_id'] = self::is_valid_steward_user_id( $candidate ) ? $candidate : 0;
		} else {
			$sanitized['deprovision_steward_user_id'] = (int) ( $current['deprovision_steward_user_id'] ?? self::DEFAULTS['deprovision_steward_user_id'] );
		}

		update_option( self::OPTION_KEY, $sanitized );

		return new \WP_REST_Response( self::read(), 200 );
	}

	// ── Public static reader (used by SecurityManager) ──────────────────────

	/**
	 * Read the consolidated settings option.
	 *
	 * @return array<string, mixed>
	 */
	public static function read(): array {
		$raw = get_option( self::OPTION_KEY, array() );

		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		$ceiling = isset( $raw['role_ceiling'] ) && in_array( $raw['role_ceiling'], self::ALLOWED_CEILINGS, true )
			? $raw['role_ceiling']
			: self::DEFAULTS['role_ceiling'];

		$timeout = isset( $raw['session_timeout'] ) && in_array( (int) $raw['session_timeout'], self::ALLOWED_TIMEOUTS, true )
			? (int) $raw['session_timeout']
			: self::DEFAULTS['session_timeout'];

		$steward_user_id = self::read_deprovision_steward_user_id();

		return array(
			'lockdown_mode'   => isset( $raw['lockdown_mode'] ) ? (bool) $raw['lockdown_mode'] : self::DEFAULTS['lockdown_mode'],
			'app_passwords'   => isset( $raw['app_passwords'] ) ? (bool) $raw['app_passwords'] : self::DEFAULTS['app_passwords'],
			'role_ceiling'    => $ceiling,
			'session_timeout' => $timeout,
			'deprovision_steward_user_id' => $steward_user_id,
			'deprovision_steward_user'    => self::format_steward_user( $steward_user_id ),
			'deprovision_steward_options' => self::get_steward_options(),
		);
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
		$raw = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			return self::DEFAULTS['deprovision_steward_user_id'];
		}

		return isset( $raw['deprovision_steward_user_id'] ) ? (int) $raw['deprovision_steward_user_id'] : self::DEFAULTS['deprovision_steward_user_id'];
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
