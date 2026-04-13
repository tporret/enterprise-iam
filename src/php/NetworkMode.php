<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class NetworkMode {

	public static function is_network_mode(): bool {
		if ( ! is_multisite() ) {
			return false;
		}

		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		return function_exists( 'is_plugin_active_for_network' )
			&& is_plugin_active_for_network( plugin_basename( ENTERPRISE_AUTH_FILE ) );
	}

	public static function is_network_idp_control_plane_active(): bool {
		return self::is_network_mode() && NetworkIdpManager::has_any();
	}
}