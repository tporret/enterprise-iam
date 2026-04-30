<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class NetworkSettingsSourceAdapter implements SettingsSourceInterface {

	private const OPTION_KEY = 'enterprise_auth_settings';
	private const NETWORK_DEFAULTS_OPTION_KEY = 'enterprise_auth_network_defaults';
	private const NETWORK_POLICY_OPTION_KEY = 'enterprise_auth_network_policy';

	public function usesNetworkSettings(): bool {
		return true;
	}

	/**
	 * @return array<string, mixed>
	 */
	public function readLocalSettingsRaw(): array {
		$raw = get_option( self::OPTION_KEY, array() );

		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * @return array<string, mixed>
	 */
	public function readNetworkDefaultsRaw(): array {
		$raw = get_site_option( self::NETWORK_DEFAULTS_OPTION_KEY, array() );

		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * @return array<string, mixed>
	 */
	public function readNetworkPolicyRaw(): array {
		$raw = get_site_option( self::NETWORK_POLICY_OPTION_KEY, array() );

		return is_array( $raw ) ? $raw : array();
	}
}
