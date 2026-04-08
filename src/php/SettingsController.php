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
	}

	private const OPTION_KEY = 'enterprise_auth_settings';

	private const DEFAULTS = array(
		'lockdown_mode'   => true,
		'app_passwords'   => false,
		'role_ceiling'    => 'editor',
		'session_timeout' => 8,
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

		update_option( self::OPTION_KEY, $sanitized );

		return new \WP_REST_Response( self::read(), 200 );
	}

	// ── Public static reader (used by SecurityManager) ──────────────────────

	/**
	 * Read the consolidated settings option.
	 *
	 * @return array<string, bool>
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

		return array(
			'lockdown_mode'   => isset( $raw['lockdown_mode'] ) ? (bool) $raw['lockdown_mode'] : self::DEFAULTS['lockdown_mode'],
			'app_passwords'   => isset( $raw['app_passwords'] ) ? (bool) $raw['app_passwords'] : self::DEFAULTS['app_passwords'],
			'role_ceiling'    => $ceiling,
			'session_timeout' => $timeout,
		);
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
		);
	}
}
