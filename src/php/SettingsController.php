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
		'lockdown_mode' => true,
		'app_passwords' => false,
	);

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

		// Only allow known keys through; cast every value to boolean.
		$sanitized = array();
		foreach ( self::DEFAULTS as $key => $default ) {
			$sanitized[ $key ] = isset( $params[ $key ] )
				? rest_sanitize_boolean( $params[ $key ] )
				: $current[ $key ];
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

		return array(
			'lockdown_mode' => isset( $raw['lockdown_mode'] ) ? (bool) $raw['lockdown_mode'] : self::DEFAULTS['lockdown_mode'],
			'app_passwords' => isset( $raw['app_passwords'] ) ? (bool) $raw['app_passwords'] : self::DEFAULTS['app_passwords'],
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
		);
	}
}
