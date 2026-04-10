<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\SiteMetaKeys;

/**
 * SCIM 2.0 Provisioning Endpoint.
 *
 * Implements the authentication and rate-limiting layer for SCIM 2.0
 * (RFC 7644) user provisioning. Identity providers authenticate with a
 * long-lived Bearer token whose bcrypt hash is stored in wp_options.
 *
 * Routes: /enterprise-auth/v1/scim/v2/*
 */
final class ScimController {

	private const NAMESPACE    = 'enterprise-auth/v1';
	private const TOKEN_KEY    = 'enterprise_iam_scim_token';
	private const RATE_LIMIT   = 300; // requests per minute

	/**
	 * Check whether a user was provisioned via SCIM on the current site.
	 */
	private static function is_scim_managed( \WP_User $user ): bool {
		$provider = get_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ), true );
		$scim_id  = get_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ), true );
		return 'scim' === $provider || '' !== $scim_id;
	}

	/**
	 * Verify the user belongs to the current blog in Multisite.
	 */
	private static function is_on_current_blog( int $user_id ): bool {
		if ( ! is_multisite() ) {
			return true;
		}
		return is_user_member_of_blog( $user_id, get_current_blog_id() );
	}

	// ── Route registration ──────────────────────────────────────────────

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/scim/v2/Users',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'list_users' ),
					'permission_callback' => array( $this, 'authenticate_scim' ),
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'create_user' ),
					'permission_callback' => array( $this, 'authenticate_scim' ),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/scim/v2/Groups',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'list_groups' ),
					'permission_callback' => array( $this, 'authenticate_scim' ),
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'create_group' ),
					'permission_callback' => array( $this, 'authenticate_scim' ),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/scim/v2/Groups/(?P<id>[\w-]+)',
			array(
				array(
					'methods'             => 'PATCH',
					'callback'            => array( $this, 'update_group' ),
					'permission_callback' => array( $this, 'authenticate_scim' ),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/scim/v2/Users/(?P<id>[\d]+)',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_user' ),
					'permission_callback' => array( $this, 'authenticate_scim' ),
				),
				array(
					'methods'             => 'PUT',
					'callback'            => array( $this, 'replace_user' ),
					'permission_callback' => array( $this, 'authenticate_scim' ),
				),
				array(
					'methods'             => 'PATCH',
					'callback'            => array( $this, 'update_user' ),
					'permission_callback' => array( $this, 'authenticate_scim' ),
				),
				array(
					'methods'             => \WP_REST_Server::DELETABLE,
					'callback'            => array( $this, 'delete_user' ),
					'permission_callback' => array( $this, 'authenticate_scim' ),
				),
			)
		);
	}

	// ── Route callbacks (stubs — 501 until user-schema mapping is built) ─

	public function list_users( \WP_REST_Request $request ): \WP_REST_Response {
		$rate_error = $this->check_rate_limit();
		if ( is_wp_error( $rate_error ) ) {
			return self::scim_error_response( $rate_error );
		}

		// SCIM pagination: startIndex is 1-based, count is page size.
		$start_index = max( 1, (int) ( $request->get_param( 'startIndex' ) ?? 1 ) );
		$count       = max( 1, min( 100, (int) ( $request->get_param( 'count' ) ?? 100 ) ) );
		$filter      = sanitize_text_field( $request->get_param( 'filter' ) ?? '' );

		$args = array(
			'number'       => $count,
			'offset'       => $start_index - 1,
			'fields'       => 'all',
			'role__not_in' => array( 'administrator' ),
		);

		// Support basic "userName eq \"value\"" filter (Okta / Azure AD connection test).
		if ( '' !== $filter && preg_match( '/userName\s+eq\s+"([^"]+)"/i', $filter, $m ) ) {
			$args['search']         = sanitize_email( $m[1] );
			$args['search_columns'] = array( 'user_email' );
		}

		$user_query  = new \WP_User_Query( $args );
		$users       = $user_query->get_results();
		$total       = $user_query->get_total();
		$resources   = array();

		foreach ( $users as $user ) {
			$resources[] = self::format_scim_user( $user );
		}

		return new \WP_REST_Response(
			array(
				'schemas'      => array( 'urn:ietf:params:scim:api:messages:2.0:ListResponse' ),
				'totalResults' => $total,
				'startIndex'   => $start_index,
				'itemsPerPage' => $count,
				'Resources'    => $resources,
			),
			200
		);
	}

	public function create_user( \WP_REST_Request $request ): \WP_REST_Response {
		$rate_error = $this->check_rate_limit();
		if ( is_wp_error( $rate_error ) ) {
			return self::scim_error_response( $rate_error );
		}

		$body = $request->get_json_params();
		if ( empty( $body ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_bad_request',
				'Request body must be valid JSON.',
				array( 'status' => 400 )
			) );
		}

		// ── Parse SCIM Core User attributes (RFC 7643 §4.1) ────────────
		$user_name   = sanitize_email( $body['userName'] ?? '' );
		$external_id = sanitize_text_field( $body['externalId'] ?? '' );
		$given_name  = sanitize_text_field( $body['name']['givenName'] ?? '' );
		$family_name = sanitize_text_field( $body['name']['familyName'] ?? '' );
		$active      = $body['active'] ?? true;

		if ( empty( $user_name ) || ! is_email( $user_name ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_bad_request',
				'A valid email address is required in the "userName" field.',
				array( 'status' => 400 )
			) );
		}

		// ── Conflict detection ──────────────────────────────────────────
		// Check by SCIM externalId first.
		if ( '' !== $external_id ) {
			$existing = self::find_user_by_scim_id( $external_id );
			if ( $existing ) {
				return self::scim_error_response( new \WP_Error(
					'scim_conflict',
					sprintf( 'A user with externalId "%s" already exists (WP ID %d).', $external_id, $existing->ID ),
					array( 'status' => 409 )
				) );
			}
		}

		// Check by email / userName.
		$existing = get_user_by( 'email', $user_name );
		if ( $existing && self::is_on_current_blog( $existing->ID ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_conflict',
				sprintf( 'A user with userName "%s" already exists (WP ID %d).', $user_name, $existing->ID ),
				array( 'status' => 409 )
			) );
		}

		// Protect against provisioning an email that belongs to an admin.
		$admin_by_login = get_user_by( 'login', $user_name );
		if ( $admin_by_login && ( 1 === $admin_by_login->ID || in_array( 'administrator', (array) $admin_by_login->roles, true ) ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_forbidden',
				'Administrator accounts cannot be provisioned via SCIM.',
				array( 'status' => 403 )
			) );
		}

		// ── Create the WordPress user ───────────────────────────────────
		$login   = self::generate_username( $user_name );
		$display = trim( "$given_name $family_name" );
		if ( '' === $display ) {
			$display = $login;
		}

		$user_id = wp_insert_user(
			array(
				'user_login'   => $login,
				'user_email'   => $user_name,
				'user_pass'    => wp_generate_password( 32, true, true ),
				'first_name'   => $given_name,
				'last_name'    => $family_name,
				'display_name' => $display,
				'role'         => $active ? 'subscriber' : '',
			)
		);

		if ( is_wp_error( $user_id ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_internal',
				'Failed to create user: ' . $user_id->get_error_message(),
				array( 'status' => 500 )
			) );
		}

		// Store SCIM binding meta.
		if ( '' !== $external_id ) {
			update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ), $external_id );
		}
		update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ), 'scim' );

		$user = get_user_by( 'id', $user_id );

		return new \WP_REST_Response( self::format_scim_user( $user ), 201 );
	}

	public function get_user( \WP_REST_Request $request ): \WP_REST_Response {
		$rate_error = $this->check_rate_limit();
		if ( is_wp_error( $rate_error ) ) {
			return self::scim_error_response( $rate_error );
		}

		$wp_user_id = (int) $request->get_param( 'id' );
		$user       = get_user_by( 'id', $wp_user_id );

		if ( ! $user || ! self::is_on_current_blog( $user->ID ) || ! self::is_scim_managed( $user ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_not_found',
				sprintf( 'User %d not found.', $wp_user_id ),
				array( 'status' => 404 )
			) );
		}

		return new \WP_REST_Response( self::format_scim_user( $user ), 200 );
	}

	public function replace_user( \WP_REST_Request $request ): \WP_REST_Response {
		$rate_error = $this->check_rate_limit();
		if ( is_wp_error( $rate_error ) ) {
			return self::scim_error_response( $rate_error );
		}

		$wp_user_id = (int) $request->get_param( 'id' );
		$user       = get_user_by( 'id', $wp_user_id );
		if ( ! $user || ! self::is_on_current_blog( $user->ID ) || ! self::is_scim_managed( $user ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_not_found',
				sprintf( 'User %d not found.', $wp_user_id ),
				array( 'status' => 404 )
			) );
		}

		// Protect administrator / break-glass accounts.
		if ( 1 === $user->ID || in_array( 'administrator', (array) $user->roles, true ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_forbidden',
				'Administrator accounts cannot be managed via SCIM.',
				array( 'status' => 403 )
			) );
		}

		$body = $request->get_json_params();
		if ( empty( $body ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_bad_request',
				'Request body must be valid JSON.',
				array( 'status' => 400 )
			) );
		}

		$user_name   = sanitize_email( $body['userName'] ?? '' );
		$external_id = sanitize_text_field( $body['externalId'] ?? '' );
		$given_name  = sanitize_text_field( $body['name']['givenName'] ?? '' );
		$family_name = sanitize_text_field( $body['name']['familyName'] ?? '' );
		$active      = $body['active'] ?? true;

		if ( empty( $user_name ) || ! is_email( $user_name ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_bad_request',
				'A valid email address is required in the "userName" field.',
				array( 'status' => 400 )
			) );
		}

		// Check for email collision with a different user.
		$email_owner = get_user_by( 'email', $user_name );
		if ( $email_owner && $email_owner->ID !== $user->ID ) {
			return self::scim_error_response( new \WP_Error(
				'scim_conflict',
				sprintf( 'Email "%s" is already in use by a different user.', $user_name ),
				array( 'status' => 409 )
			) );
		}

		$display = trim( "$given_name $family_name" );
		if ( '' === $display ) {
			$display = $user->user_login;
		}

		$result = wp_update_user(
			array(
				'ID'           => $user->ID,
				'user_email'   => $user_name,
				'first_name'   => $given_name,
				'last_name'    => $family_name,
				'display_name' => $display,
				'role'         => $active ? ( $user->roles[0] ?? 'subscriber' ) : '',
			)
		);

		if ( is_wp_error( $result ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_internal',
				'Failed to update user: ' . $result->get_error_message(),
				array( 'status' => 500 )
			) );
		}

		// When the user is being suspended (active=false), destroy all
		// active sessions and flag the account — mirrors PATCH behaviour.
		if ( ! $active ) {
			update_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ), 'true' );
			\WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
		} else {
			delete_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ) );
		}

		if ( '' !== $external_id ) {
			update_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ), $external_id );
		}

		$user = get_user_by( 'id', $user->ID );

		return new \WP_REST_Response( self::format_scim_user( $user ), 200 );
	}

	public function update_user( \WP_REST_Request $request ): \WP_REST_Response {
		$rate_error = $this->check_rate_limit();
		if ( is_wp_error( $rate_error ) ) {
			return self::scim_error_response( $rate_error );
		}

		$wp_user_id = (int) $request->get_param( 'id' );
		$user       = get_user_by( 'id', $wp_user_id );
		if ( ! $user || ! self::is_on_current_blog( $user->ID ) || ! self::is_scim_managed( $user ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_not_found',
				sprintf( 'User %d not found.', $wp_user_id ),
				array( 'status' => 404 )
			) );
		}

		// Protect administrator / break-glass accounts.
		if ( 1 === $user->ID || in_array( 'administrator', (array) $user->roles, true ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_forbidden',
				'Administrator accounts cannot be managed via SCIM.',
				array( 'status' => 403 )
			) );
		}

		$body = $request->get_json_params();
		if ( empty( $body ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_bad_request',
				'Request body must be valid JSON.',
				array( 'status' => 400 )
			) );
		}

		// ── Process SCIM PatchOp (RFC 7644 §3.5.2) ─────────────────────
		$operations = $body['Operations'] ?? array();
		if ( empty( $operations ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_bad_request',
				'PATCH body must contain an "Operations" array.',
				array( 'status' => 400 )
			) );
		}

		foreach ( $operations as $op ) {
			$op_type = strtolower( $op['op'] ?? '' );
			$path    = $op['path'] ?? '';
			$value   = $op['value'] ?? null;

			if ( 'replace' === $op_type && 'active' === $path ) {
				$active = filter_var( $value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE );
				if ( null === $active ) {
					continue;
				}

				if ( ! $active ) {
					// Suspend: remove all roles, flag, and destroy active sessions.
					$user->set_role( '' );
					update_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ), 'true' );
					\WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
				} else {
					// Reactivate: restore default role and clear the flag.
					$user->set_role( 'subscriber' );
					delete_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ) );
				}
			}

			// Handle top-level "active" in value object (Azure AD style).
			if ( 'replace' === $op_type && empty( $path ) && is_array( $value ) && array_key_exists( 'active', $value ) ) {
				$active = filter_var( $value['active'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE );
				if ( null === $active ) {
					continue;
				}

				if ( ! $active ) {
					$user->set_role( '' );
					update_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ), 'true' );
					\WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
				} else {
					$user->set_role( 'subscriber' );
					delete_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ) );
				}
			}
		}

		// Refresh user object after modifications.
		$user = get_user_by( 'id', $user->ID );

		return new \WP_REST_Response( self::format_scim_user( $user ), 200 );
	}

	public function delete_user( \WP_REST_Request $request ): \WP_REST_Response {
		$rate_error = $this->check_rate_limit();
		if ( is_wp_error( $rate_error ) ) {
			return self::scim_error_response( $rate_error );
		}
		return self::not_implemented();
	}

	// ── Group callbacks ──────────────────────────────────────────────────

	/**
	 * GET /scim/v2/Groups — list WordPress roles as SCIM Group resources.
	 *
	 * Returns each registered WordPress role as a SCIM Group. This allows
	 * IdP connectors (Okta, Azure AD, MidPoint) to discover available
	 * groups during connection setup and reconciliation.
	 */
	public function list_groups( \WP_REST_Request $request ): \WP_REST_Response {
		$rate_error = $this->check_rate_limit();
		if ( is_wp_error( $rate_error ) ) {
			return self::scim_error_response( $rate_error );
		}

		$wp_roles  = wp_roles()->get_names();
		$resources = array();

		foreach ( $wp_roles as $slug => $label ) {
			$resources[] = array(
				'schemas'     => array( 'urn:ietf:params:scim:schemas:core:2.0:Group' ),
				'id'          => $slug,
				'displayName' => $label,
				'meta'        => array(
					'resourceType' => 'Group',
				),
			);
		}

		return new \WP_REST_Response(
			array(
				'schemas'      => array( 'urn:ietf:params:scim:api:messages:2.0:ListResponse' ),
				'totalResults' => count( $resources ),
				'startIndex'   => 1,
				'itemsPerPage' => count( $resources ),
				'Resources'    => $resources,
			),
			200
		);
	}

	/**
	 * POST /scim/v2/Groups — create a group and assign roles to members.
	 *
	 * The IdP sends a group resource with a displayName (mapped to a WP
	 * role via the existing role-mapping engine) and a list of members
	 * (WordPress User IDs). Each member receives the resolved role.
	 */
	public function create_group( \WP_REST_Request $request ): \WP_REST_Response {
		$rate_error = $this->check_rate_limit();
		if ( is_wp_error( $rate_error ) ) {
			return self::scim_error_response( $rate_error );
		}

		$body = $request->get_json_params();
		if ( empty( $body ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_bad_request',
				'Request body must be valid JSON.',
				array( 'status' => 400 )
			) );
		}

		$display_name = sanitize_text_field( $body['displayName'] ?? '' );
		if ( '' === $display_name ) {
			return self::scim_error_response( new \WP_Error(
				'scim_bad_request',
				'The "displayName" attribute is required.',
				array( 'status' => 400 )
			) );
		}

		$members = $body['members'] ?? array();
		if ( count( $members ) > self::MAX_GROUP_MEMBERS ) {
			return self::scim_error_response( new \WP_Error(
				'scim_bad_request',
				sprintf( 'Too many members. Maximum is %d per operation.', self::MAX_GROUP_MEMBERS ),
				array( 'status' => 400 )
			) );
		}
		self::apply_group_to_members( $display_name, $members );

		return new \WP_REST_Response( self::format_scim_group( $display_name, $members ), 201 );
	}

	/**
	 * PATCH /scim/v2/Groups/{id} — update group membership.
	 *
	 * Processes RFC 7644 PatchOp operations to add/replace members.
	 */
	public function update_group( \WP_REST_Request $request ): \WP_REST_Response {
		$rate_error = $this->check_rate_limit();
		if ( is_wp_error( $rate_error ) ) {
			return self::scim_error_response( $rate_error );
		}

		$body = $request->get_json_params();
		if ( empty( $body ) ) {
			return self::scim_error_response( new \WP_Error(
				'scim_bad_request',
				'Request body must be valid JSON.',
				array( 'status' => 400 )
			) );
		}

		$display_name = sanitize_text_field( $body['displayName'] ?? '' );
		$operations   = $body['Operations'] ?? array();

		// Collect members from Operations, enforcing the member cap early
		// to prevent unbounded memory allocation from malicious payloads.
		$members = array();
		foreach ( $operations as $op ) {
			$op_type = strtolower( $op['op'] ?? '' );
			$path    = $op['path'] ?? '';
			$value   = $op['value'] ?? array();

			if ( in_array( $op_type, array( 'add', 'replace' ), true ) && 'members' === $path && is_array( $value ) ) {
				foreach ( $value as $member ) {
					$members[] = $member;
					if ( count( $members ) > self::MAX_GROUP_MEMBERS ) {
						return self::scim_error_response( new \WP_Error(
							'scim_bad_request',
							sprintf( 'Too many members. Maximum is %d per operation.', self::MAX_GROUP_MEMBERS ),
							array( 'status' => 400 )
						) );
					}
				}
			}
		}

		if ( '' !== $display_name && ! empty( $members ) ) {
			self::apply_group_to_members( $display_name, $members );
		}

		return new \WP_REST_Response( null, 204 );
	}

	/**
	 * Apply a SCIM group's displayName as a role to each member.
	 *
	 * @param string  $display_name The SCIM group displayName.
	 * @param array[] $members      Array of member objects with 'value' (User ID).
	 */
	private const MAX_GROUP_MEMBERS = 1000;

	private static function apply_group_to_members( string $display_name, array $members ): void {
		$members = array_slice( $members, 0, self::MAX_GROUP_MEMBERS );
		foreach ( $members as $member ) {
			$user_id = (int) ( $member['value'] ?? 0 );
			if ( $user_id < 1 ) {
				continue;
			}

			$user = get_user_by( 'id', $user_id );
			if ( ! $user || ! self::is_on_current_blog( $user->ID ) ) {
				continue;
			}

			// Skip administrators / break-glass accounts.
			if ( 1 === $user->ID || in_array( 'administrator', (array) $user->roles, true ) ) {
				continue;
			}

			\EnterpriseAuth\Plugin\EnterpriseProvisioning::assign_role( $user, array( $display_name ) );
		}
	}

	/**
	 * Format a SCIM Group response (RFC 7643 §4.2).
	 *
	 * @param string  $display_name Group displayName.
	 * @param array[] $members      Member objects.
	 * @return array<string, mixed>
	 */
	private static function format_scim_group( string $display_name, array $members ): array {
		$formatted_members = array();
		foreach ( $members as $member ) {
			$value = $member['value'] ?? '';
			if ( '' !== $value ) {
				$formatted_members[] = array(
					'value'   => (string) $value,
					'\$ref'   => rest_url( self::NAMESPACE . '/scim/v2/Users/' . $value ),
					'display' => $member['display'] ?? '',
				);
			}
		}

		return array(
			'schemas'     => array( 'urn:ietf:params:scim:schemas:core:2.0:Group' ),
			'id'          => sanitize_title( $display_name ),
			'displayName' => $display_name,
			'members'     => $formatted_members,
			'meta'        => array(
				'resourceType' => 'Group',
			),
		);
	}

	// ── Bearer Token Authentication ─────────────────────────────────────

	/**
	 * Verify the Authorization: Bearer header against the stored bcrypt hash.
	 *
	 * @return true|\WP_Error
	 */
	public function authenticate_scim( \WP_REST_Request $request ) {
		$result = $this->authenticate_bearer_token( $request );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		return true;
	}

	/**
	 * Extract and verify the Bearer token from the Authorization header.
	 *
	 * The plaintext token is supplied by the IdP during SCIM configuration.
	 * The admin stores only the bcrypt hash via wp_hash_password() in
	 * wp_options under the key `enterprise_iam_scim_token`.
	 *
	 * @return true|\WP_Error
	 */
	private function authenticate_bearer_token( \WP_REST_Request $request ) {
		// 1. Extract the Authorization header.
		$auth_header = $request->get_header( 'Authorization' );

		if ( empty( $auth_header ) ) {
			return new \WP_Error(
				'rest_forbidden',
				'Missing Authorization header. A Bearer token is required.',
				array( 'status' => 401 )
			);
		}

		// 2. Ensure it's a Bearer scheme.
		if ( ! preg_match( '/^Bearer\s+(.+)$/i', $auth_header, $matches ) ) {
			return new \WP_Error(
				'rest_forbidden',
				'Invalid Authorization header. Expected "Bearer <token>".',
				array( 'status' => 401 )
			);
		}

		$token = $matches[1];

		// 3. Retrieve the stored hash.
		$stored_hash = get_option( self::TOKEN_KEY, '' );

		if ( empty( $stored_hash ) ) {
			return new \WP_Error(
				'rest_forbidden',
				'SCIM provisioning token has not been configured.',
				array( 'status' => 401 )
			);
		}

		// 4. Constant-time comparison via wp_check_password (bcrypt).
		if ( ! wp_check_password( $token, $stored_hash ) ) {
			return new \WP_Error(
				'rest_forbidden',
				'Invalid SCIM Bearer token.',
				array( 'status' => 401 )
			);
		}

		return true;
	}

	// ── Rate Limiting ───────────────────────────────────────────────────

	/**
	 * Sliding-window rate limiter using WordPress transients.
	 *
	 * Tracks the request count in the current 60-second window. If the
	 * count exceeds the threshold (300 req/min), a 429 error is returned.
	 * This protects against runaway IdP syncs hammering the site.
	 *
	 * @return null|\WP_Error Null on success, WP_Error if rate exceeded.
	 */
	private function check_rate_limit(): ?\WP_Error {
		$window_key = 'ea_scim_rate_' . (string) intdiv( time(), 60 );
		$count      = (int) get_transient( $window_key );

		++$count;
		set_transient( $window_key, $count, 120 ); // TTL 2 min to cover window edge.

		if ( $count > self::RATE_LIMIT ) {
			return new \WP_Error(
				'scim_rate_limit',
				sprintf( 'Rate limit exceeded. Maximum %d requests per minute.', self::RATE_LIMIT ),
				array( 'status' => 429 )
			);
		}

		return null;
	}

	// ── Helpers ─────────────────────────────────────────────────────────

	/**
	 * Standard SCIM 501 response for unimplemented operations.
	 */
	private static function not_implemented(): \WP_REST_Response {
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
	 * Convert a WP_Error to a SCIM-formatted JSON error response.
	 */
	private static function scim_error_response( \WP_Error $error ): \WP_REST_Response {
		$data   = $error->get_error_data();
		$status = is_array( $data ) && isset( $data['status'] ) ? (int) $data['status'] : 500;

		return new \WP_REST_Response(
			array(
				'schemas' => array( 'urn:ietf:params:scim:api:messages:2.0:Error' ),
				'detail'  => $error->get_error_message(),
				'status'  => $status,
			),
			$status
		);
	}

	// ── SCIM User helpers ───────────────────────────────────────────────

	/**
	 * Find a WordPress user by the stored SCIM externalId.
	 */
	private static function find_user_by_scim_id( string $external_id ): ?\WP_User {
		if ( '' === $external_id ) {
			return null;
		}

		$users = get_users(
			array(
				'meta_key'   => SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ),
				'meta_value' => $external_id,
				'number'     => 1,
				'fields'     => 'all',
			)
		);

		return ! empty( $users ) ? $users[0] : null;
	}

	/**
	 * Derive a unique username from an email address.
	 */
	private static function generate_username( string $email ): string {
		$base = sanitize_user( strtok( $email, '@' ), true );

		if ( ! username_exists( $base ) ) {
			return $base;
		}

		$i = 2;
		while ( username_exists( $base . $i ) ) {
			++$i;
		}

		return $base . $i;
	}

	/**
	 * Format a WordPress user as a SCIM Core User resource (RFC 7643 §4.1).
	 *
	 * @return array<string, mixed>
	 */
	private static function format_scim_user( \WP_User $user ): array {
		$scim_id = get_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ), true );

		$resource = array(
			'schemas'    => array( 'urn:ietf:params:scim:schemas:core:2.0:User' ),
			'id'         => (string) $user->ID,
			'userName'   => $user->user_email,
			'name'       => array(
				'givenName'  => $user->first_name,
				'familyName' => $user->last_name,
			),
			'displayName' => $user->display_name,
			'active'      => ! empty( $user->roles ),
			'meta'        => array(
				'resourceType' => 'User',
				'created'      => get_date_from_gmt( $user->user_registered, 'Y-m-d\TH:i:s\Z' ),
				'location'     => rest_url( self::NAMESPACE . '/scim/v2/Users/' . $user->ID ),
			),
		);

		if ( '' !== $scim_id ) {
			$resource['externalId'] = $scim_id;
		}

		return $resource;
	}
}
