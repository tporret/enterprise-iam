<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EffectiveSettingsResolver {

	private const OPTION_KEY = 'enterprise_auth_settings';
	private const NETWORK_DEFAULTS_OPTION_KEY = 'enterprise_auth_network_defaults';
	private const NETWORK_POLICY_OPTION_KEY = 'enterprise_auth_network_policy';
	private const BOOLEAN_KEYS = array( 'lockdown_mode', 'app_passwords', 'require_device_bound_authenticators', 'private_content_login_required' );
	private const NETWORK_DEFAULT_KEYS = array( 'lockdown_mode', 'app_passwords', 'require_device_bound_authenticators', 'private_content_login_required', 'role_ceiling', 'session_timeout' );

	private const DEFAULTS = array(
		'lockdown_mode' => true,
		'app_passwords' => false,
		'require_device_bound_authenticators' => false,
		'private_content_login_required' => false,
		'role_ceiling' => 'editor',
		'session_timeout' => 8,
		'deprovision_steward_user_id' => 0,
	);

	private const NETWORK_POLICY_DEFAULTS = array(
		'allow_site_overrides' => array(
			'lockdown_mode' => false,
			'app_passwords' => false,
			'require_device_bound_authenticators' => true,
			'private_content_login_required' => true,
			'role_ceiling' => false,
			'session_timeout' => true,
			'deprovision_steward_user_id' => true,
		),
		'allow_site_role_mappings' => true,
		'allow_site_scim' => true,
	);

	private const ALLOWED_CEILINGS = array( 'editor', 'author', 'contributor', 'subscriber' );
	private const ALLOWED_TIMEOUTS = array( 1, 2, 4, 8, 12, 24 );

	public static function defaults(): array {
		return self::DEFAULTS;
	}

	public static function network_default_keys(): array {
		return self::NETWORK_DEFAULT_KEYS;
	}

	public static function uses_network_settings(): bool {
		return NetworkMode::is_network_mode();
	}

	public static function read(): array {
		$resolved = self::resolve();
		$values   = $resolved['values'];
		$values['scope_meta'] = $resolved['meta'];

		return $values;
	}

	public static function resolve(): array {
		if ( self::uses_network_settings() ) {
			return self::resolve_network_settings();
		}

		return self::resolve_single_site_settings();
	}

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
			'private_content_login_required' => (bool) $defaults['private_content_login_required'],
			'role_ceiling' => (string) $defaults['role_ceiling'],
			'session_timeout' => (int) $defaults['session_timeout'],
		);
	}

	public static function read_network_policy(): array {
		$raw = get_site_option( self::NETWORK_POLICY_OPTION_KEY, array() );

		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		return self::sanitize_network_policy( $raw );
	}

	public static function read_network_settings_payload(): array {
		return array(
			'defaults' => self::read_network_defaults(),
			'policy' => self::read_network_policy(),
		);
	}

	public static function read_local_settings(): array {
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

	public static function sanitize_settings_payload( array $params, array $fallback, bool $include_deprovision ): array {
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

	public static function sanitize_network_policy( array $policy ): array {
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

	public static function site_can_override( string $key, array $policy ): bool {
		return ! empty( $policy['allow_site_overrides'][ $key ] );
	}

	public static function read_deprovision_steward_user_id(): int {
		$candidate = self::read_raw_deprovision_steward_user_id();

		return self::is_valid_steward_user_id( $candidate ) ? $candidate : self::DEFAULTS['deprovision_steward_user_id'];
	}

	public static function read_raw_deprovision_steward_user_id(): int {
		$raw = self::read_local_settings();
		if ( ! isset( $raw['deprovision_steward_user_id'] ) ) {
			return self::DEFAULTS['deprovision_steward_user_id'];
		}

		return (int) $raw['deprovision_steward_user_id'];
	}

	private static function resolve_single_site_settings(): array {
		$local_settings  = self::read_local_settings();
		$steward_user_id = self::read_deprovision_steward_user_id();
		$meta            = array();

		foreach ( self::NETWORK_DEFAULT_KEYS as $key ) {
			$meta[ $key ] = self::build_scope_meta(
				'site_only',
				true,
				'This setting is configured on this site only.'
			);
		}

		$meta['deprovision_steward_user_id'] = self::build_scope_meta(
			'site_only',
			true,
			'This setting is configured on this site only.'
		);

		return array(
			'values' => array(
				'lockdown_mode' => (bool) ( $local_settings['lockdown_mode'] ?? self::DEFAULTS['lockdown_mode'] ),
				'app_passwords' => (bool) ( $local_settings['app_passwords'] ?? self::DEFAULTS['app_passwords'] ),
				'require_device_bound_authenticators' => (bool) ( $local_settings['require_device_bound_authenticators'] ?? self::DEFAULTS['require_device_bound_authenticators'] ),
				'role_ceiling' => (string) ( $local_settings['role_ceiling'] ?? self::DEFAULTS['role_ceiling'] ),
				'session_timeout' => (int) ( $local_settings['session_timeout'] ?? self::DEFAULTS['session_timeout'] ),
				'deprovision_steward_user_id' => $steward_user_id,
				'deprovision_steward_options' => self::get_steward_options(),
			),
			'meta' => $meta,
		);
	}

	private static function resolve_network_settings(): array {
		$network_defaults = self::read_network_defaults();
		$network_policy   = self::read_network_policy();
		$local_settings   = self::read_local_settings();
		$values           = array();
		$meta             = array();

		foreach ( self::NETWORK_DEFAULT_KEYS as $key ) {
			$can_override    = self::site_can_override( $key, $network_policy );
			$has_override    = $can_override && array_key_exists( $key, $local_settings );
			$network_default = $network_defaults[ $key ];

			$values[ $key ] = $has_override ? $local_settings[ $key ] : $network_default;

			if ( $has_override ) {
				$meta[ $key ] = self::build_scope_meta(
					'site_override',
					true,
					'This site overrides the current network default.',
					$network_default,
					true
				);
				continue;
			}

			if ( $can_override ) {
				$meta[ $key ] = self::build_scope_meta(
					'inherited',
					true,
					'This site is currently using the network default. Saving a new value will create a site override.',
					$network_default,
					true
				);
				continue;
			}

			$meta[ $key ] = self::build_scope_meta(
				'locked_by_network',
				false,
				'This setting is managed in Network Admin and cannot be overridden on this site.',
				$network_default,
				false
			);
		}

		$values['deprovision_steward_user_id'] = self::read_deprovision_steward_user_id();
		$values['deprovision_steward_options'] = self::get_steward_options();
		$meta['deprovision_steward_user_id'] = self::build_scope_meta(
			'site_only',
			true,
			'This setting remains site-scoped in network mode.'
		);

		return array(
			'values' => $values,
			'meta' => $meta,
		);
	}

	private static function build_scope_meta( string $state, bool $editable, string $description, mixed $network_default = null, ?bool $overridable = null ): array {
		$label = match ( $state ) {
			'site_override' => 'Overridden on This Site',
			'inherited' => 'Inherited from Network',
			'locked_by_network' => 'Locked by Network Policy',
			'network_default' => 'Network Default',
			default => 'Site Only',
		};

		$tone = match ( $state ) {
			'site_override' => 'override',
			'inherited' => 'inherited',
			'locked_by_network' => 'locked',
			'network_default' => 'network',
			default => 'site-only',
		};

		$scope = match ( $state ) {
			'site_override', 'site_only' => 'site',
			default => 'network',
		};

		$meta = array(
			'state' => $state,
			'scope' => $scope,
			'label' => $label,
			'tone' => $tone,
			'editable' => $editable,
			'overridable' => null !== $overridable ? $overridable : $editable,
			'description' => $description,
		);

		if ( null !== $network_default ) {
			$meta['network_default'] = $network_default;
		}

		return $meta;
	}

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

	private static function get_steward_options(): array {
		$args = array(
			'fields' => 'all',
			'orderby' => 'display_name',
			'order' => 'ASC',
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
				'id' => $user->ID,
				'label' => sprintf( '%s (%s, ID %d)', $user->display_name ?: $user->user_login, $user->user_email ?: $user->user_login, $user->ID ),
			);
		}

		return $options;
	}
}