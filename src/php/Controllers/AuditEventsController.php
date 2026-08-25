<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\AuditLogger;

final class AuditEventsController {

	private const NAMESPACE = 'enterprise-auth/v1';
	private const ROUTE     = '/audit-events';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			self::ROUTE,
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'list_events' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);
	}

	public function check_permission(): bool {
		return current_user_can( 'manage_options' ) || current_user_can( 'manage_network_options' );
	}

	public function list_events( \WP_REST_Request $request ): \WP_REST_Response {
		$limit  = (int) ( $request->get_param( 'per_page' ) ? $request->get_param( 'per_page' ) : 100 );
		$events = AuditLogger::events( $limit );

		return new \WP_REST_Response(
			array(
				'items' => $events,
				'total' => count( $events ),
			),
			200
		);
	}
}
