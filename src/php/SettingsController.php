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
	private const SCIM_TOKEN_OPTION = 'enterprise_iam_scim_token';

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

		$local_settings = EffectiveSettingsResolver::read_local_settings();
		$sanitized      = EffectiveSettingsResolver::sanitize_settings_payload( $params, $local_settings, true );

		if ( ! EffectiveSettingsResolver::uses_network_settings() ) {
			update_option( self::OPTION_KEY, $sanitized );

			$current_effective = self::read();
			self::sync_device_bound_policy_transition(
				(bool) ( $previous_effective['require_device_bound_authenticators'] ?? EffectiveSettingsResolver::defaults()['require_device_bound_authenticators'] ),
				(bool) ( $current_effective['require_device_bound_authenticators'] ?? EffectiveSettingsResolver::defaults()['require_device_bound_authenticators'] )
			);

			return new \WP_REST_Response( $current_effective, 200 );
		}

		$network_defaults = EffectiveSettingsResolver::read_network_defaults();
		$network_policy   = EffectiveSettingsResolver::read_network_policy();
		$locked_fields    = array();

		foreach ( EffectiveSettingsResolver::network_default_keys() as $key ) {
			if ( array_key_exists( $key, $params ) && ! EffectiveSettingsResolver::site_can_override( $key, $network_policy ) ) {
				$locked_fields[] = $key;
			}

			if ( ! EffectiveSettingsResolver::site_can_override( $key, $network_policy ) ) {
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

		if ( array() !== $locked_fields ) {
			return new \WP_REST_Response(
				array(
					'error' => 'One or more requested settings are locked by network policy.',
					'code' => 'locked_by_network_policy',
					'locked_fields' => array_values( array_unique( $locked_fields ) ),
				),
				403
			);
		}

		if ( array_key_exists( 'deprovision_steward_user_id', $params ) ) {
			$local_settings['deprovision_steward_user_id'] = $sanitized['deprovision_steward_user_id'];
		}

		update_option( self::OPTION_KEY, $local_settings );

		$current_effective = self::read();
		self::sync_device_bound_policy_transition(
			(bool) ( $previous_effective['require_device_bound_authenticators'] ?? EffectiveSettingsResolver::defaults()['require_device_bound_authenticators'] ),
			(bool) ( $current_effective['require_device_bound_authenticators'] ?? EffectiveSettingsResolver::defaults()['require_device_bound_authenticators'] )
		);

		return new \WP_REST_Response( $current_effective, 200 );
	}

	/**
	 * Read the effective settings payload for the current site context.
	 *
	 * @return array<string, mixed>
	 */
	public static function read(): array {
		return EffectiveSettingsResolver::read();
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function read_network_defaults(): array {
		return EffectiveSettingsResolver::read_network_defaults();
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function read_network_policy(): array {
		return EffectiveSettingsResolver::read_network_policy();
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function read_network_settings_payload(): array {
		return EffectiveSettingsResolver::read_network_settings_payload();
	}

	/**
	 * @param array<string, mixed> $payload
	 * @return array<string, mixed>
	 */
	public static function update_network_settings_payload( array $payload ): array {
		$previous_site_policies = self::snapshot_effective_device_bound_policy_by_site();

		$defaults_payload = isset( $payload['defaults'] ) && is_array( $payload['defaults'] ) ? $payload['defaults'] : array();
		$policy_payload   = isset( $payload['policy'] ) && is_array( $payload['policy'] ) ? $payload['policy'] : array();

		$defaults = EffectiveSettingsResolver::sanitize_settings_payload( $defaults_payload, self::read_network_defaults(), false );
		$policy   = EffectiveSettingsResolver::sanitize_network_policy( $policy_payload );

		update_site_option( self::NETWORK_DEFAULTS_OPTION_KEY, $defaults );
		update_site_option( self::NETWORK_POLICY_OPTION_KEY, $policy );

		$current_site_policies = self::snapshot_effective_device_bound_policy_by_site();
		foreach ( $current_site_policies as $blog_id => $current ) {
			$previous = $previous_site_policies[ $blog_id ] ?? EffectiveSettingsResolver::defaults()['require_device_bound_authenticators'];
			self::with_blog(
				(int) $blog_id,
				static function () use ( $previous, $current ): void {
					self::sync_device_bound_policy_transition( (bool) $previous, (bool) $current );
				}
			);
		}

		return self::read_network_settings_payload();
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
				get_current_blog_id() => (bool) ( self::read()['require_device_bound_authenticators'] ?? EffectiveSettingsResolver::defaults()['require_device_bound_authenticators'] ),
			);
		}

		$results = array();
		foreach ( get_sites( array( 'number' => 0 ) ) as $site ) {
			$blog_id = (int) $site->blog_id;
			$results[ $blog_id ] = (bool) self::with_blog(
				$blog_id,
				static fn(): bool => (bool) ( self::read()['require_device_bound_authenticators'] ?? EffectiveSettingsResolver::defaults()['require_device_bound_authenticators'] )
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
			'role_ceiling' => array(
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

	// ── SCIM Token Generation ───────────────────────────────────────────────

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
