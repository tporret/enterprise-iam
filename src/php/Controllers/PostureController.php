<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\IamPostureReporter;

final class PostureController {

	private const NAMESPACE = 'enterprise-auth/v1';
	private const ROUTE     = '/posture';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			self::ROUTE,
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_posture' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);
	}

	public function check_permission( \WP_REST_Request $request ): bool {
		if ( 'network' === $request->get_param( 'scope' ) ) {
			return current_user_can( 'manage_network_options' );
		}

		return current_user_can( 'manage_options' );
	}

	public function get_posture( \WP_REST_Request $request ): \WP_REST_Response {
		$reporter = new IamPostureReporter();
		$posture  = 'network' === $request->get_param( 'scope' )
			? $reporter->network_posture()
			: $reporter->site_posture();

		return new \WP_REST_Response( $posture, 200 );
	}
}