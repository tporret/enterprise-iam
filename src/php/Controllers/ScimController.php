<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SCIM 2.0 Provisioning Endpoint (stub).
 *
 * This controller reserves the REST namespace for future SCIM 2.0 support
 * (RFC 7644). When fully implemented it will allow identity providers to:
 *
 *  - POST   /scim/v2/Users          — Create a user
 *  - GET    /scim/v2/Users/{id}     — Read a user
 *  - PUT    /scim/v2/Users/{id}     — Replace a user
 *  - PATCH  /scim/v2/Users/{id}     — Update user attributes
 *  - DELETE /scim/v2/Users/{id}     — De-provision (disable/delete) a user
 *  - GET    /scim/v2/Users          — List/filter users
 *
 * Implementation roadmap:
 *  1. Bearer-token authentication (per-IdP SCIM token stored encrypted).
 *  2. User schema mapping (SCIM Core → WordPress user fields).
 *  3. De-provisioning strategy: disable (set role to 'none') vs delete.
 *  4. Group/role sync via /scim/v2/Groups.
 *  5. Rate limiting and audit logging.
 *
 * Route: /enterprise-auth/v1/scim/v2/*
 */
final class ScimController {

	private const NAMESPACE = 'enterprise-auth/v1';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/scim/v2/Users',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'not_implemented' ),
				'permission_callback' => array( $this, 'authenticate_scim' ),
			)
		);
	}

	/**
	 * Placeholder: return 501 Not Implemented.
	 */
	public function not_implemented( \WP_REST_Request $_request ): \WP_REST_Response {
		return new \WP_REST_Response(
			array(
				'schemas' => array( 'urn:ietf:params:scim:api:messages:2.0:Error' ),
				'detail'  => 'SCIM provisioning is not yet implemented. This endpoint is reserved for future use.',
				'status'  => 501,
			),
			501
		);
	}

	/**
	 * SCIM bearer-token authentication (stub).
	 *
	 * When implemented, this will verify the Authorization: Bearer header
	 * against per-IdP SCIM tokens stored in the database.
	 */
	public function authenticate_scim( \WP_REST_Request $_request ): bool {
		// Always deny until SCIM is fully implemented.
		return false;
	}
}
