<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\NetworkMode;
use EnterpriseAuth\Plugin\SettingsController;

final class NetworkSettingsController {

	private const NAMESPACE = 'enterprise-auth/v1';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/network/defaults',
			array(
				array(
					'methods' => \WP_REST_Server::READABLE,
					'callback' => array( $this, 'get_settings' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
				array(
					'methods' => \WP_REST_Server::CREATABLE,
					'callback' => array( $this, 'update_settings' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);
	}

	public function check_permission(): bool {
		return NetworkMode::is_network_mode() && current_user_can( 'manage_network_options' );
	}

	public function get_settings(): \WP_REST_Response {
		return new \WP_REST_Response( SettingsController::read_network_settings_payload(), 200 );
	}

	public function update_settings( \WP_REST_Request $request ): \WP_REST_Response {
		$params = $request->get_json_params();

		if ( ! is_array( $params ) ) {
			$params = array();
		}

		return new \WP_REST_Response( SettingsController::update_network_settings_payload( $params ), 200 );
	}
}