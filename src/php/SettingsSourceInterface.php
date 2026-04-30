<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

interface SettingsSourceInterface {

	public function usesNetworkSettings(): bool;

	/**
	 * @return array<string, mixed>
	 */
	public function readLocalSettingsRaw(): array;

	/**
	 * @return array<string, mixed>
	 */
	public function readNetworkDefaultsRaw(): array;

	/**
	 * @return array<string, mixed>
	 */
	public function readNetworkPolicyRaw(): array;
}
