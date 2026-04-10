<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\SiteMetaKeys;
use EnterpriseAuth\Plugin\SettingsController;

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
	private const DEPROVISION_SCOPE_SITE = 'site';
	private const DEPROVISION_SCOPE_NETWORK = 'network';

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
					'args'                => array(
						'scope' => array(
							'type'              => 'string',
							'required'          => false,
							'enum'              => array( self::DEPROVISION_SCOPE_SITE, self::DEPROVISION_SCOPE_NETWORK ),
							'sanitize_callback' => 'sanitize_text_field',
						),
					),
				),
			)
		);
	}

	// ── Route callbacks ────────────────────────────────────────────────

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

		// Multisite: if the user exists globally but is not yet a member of
		// this blog, attach them to the current tenant instead of trying to
		// create a duplicate global user record.
		if ( $existing && ! self::is_on_current_blog( $existing->ID ) ) {
			if ( 1 === $existing->ID || is_super_admin( $existing->ID ) ) {
				return self::scim_error_response( new \WP_Error(
					'scim_forbidden',
					'Administrator accounts cannot be provisioned via SCIM.',
					array( 'status' => 403 )
				) );
			}

			$added = add_user_to_blog( get_current_blog_id(), $existing->ID, 'subscriber' );
			if ( is_wp_error( $added ) ) {
				return self::scim_error_response( new \WP_Error(
					'scim_internal',
					'Failed to attach existing user to this site: ' . $added->get_error_message(),
					array( 'status' => 500 )
				) );
			}

			$display = trim( "$given_name $family_name" );
			if ( '' === $display ) {
				$display = $existing->display_name ?: $existing->user_login;
			}

			$result = wp_update_user(
				array(
					'ID'           => $existing->ID,
					'user_email'   => $user_name,
					'first_name'   => $given_name,
					'last_name'    => $family_name,
					'display_name' => $display,
				)
			);

			if ( is_wp_error( $result ) ) {
				return self::scim_error_response( new \WP_Error(
					'scim_internal',
					'Failed to update attached user: ' . $result->get_error_message(),
					array( 'status' => 500 )
				) );
			}

			$user = get_user_by( 'id', $existing->ID );
			if ( ! $user ) {
				return self::scim_error_response( new \WP_Error(
					'scim_internal',
					'Attached user could not be reloaded.',
					array( 'status' => 500 )
				) );
			}

			if ( ! $active ) {
				$user->set_role( '' );
				update_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ), 'true' );
				\WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
			} else {
				$user->set_role( 'subscriber' );
				delete_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ) );
				self::set_network_scim_suspended( $user->ID, false );
			}

			if ( '' !== $external_id ) {
				update_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ), $external_id );
			}
			update_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ), 'scim' );
			self::emit_identity_event(
				'scim_create',
				array(
					'user_id'     => $user->ID,
					'external_id' => $external_id,
					'mode'        => 'attach_existing',
				)
			);

			return new \WP_REST_Response( self::format_scim_user( $user ), 201 );
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

		if ( ! $active ) {
			update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ), 'true' );
		} else {
			delete_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ) );
			self::set_network_scim_suspended( $user_id, false );
		}

		$user = get_user_by( 'id', $user_id );
		if ( $user ) {
			self::emit_identity_event(
				'scim_create',
				array(
					'user_id'     => $user->ID,
					'external_id' => $external_id,
					'mode'        => 'create',
				)
			);
		}

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
			self::set_network_scim_suspended( $user->ID, false );
		}

		if ( '' !== $external_id ) {
			update_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ), $external_id );
		}

		$user = get_user_by( 'id', $user->ID );
		if ( $user ) {
			self::emit_identity_event(
				'scim_update',
				array(
					'user_id'     => $user->ID,
					'external_id' => $external_id,
					'method'      => 'replace',
				)
			);
		}

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
					self::set_network_scim_suspended( $user->ID, false );
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
					self::set_network_scim_suspended( $user->ID, false );
				}
			}
		}

		// Refresh user object after modifications.
		$user = get_user_by( 'id', $user->ID );
		if ( $user ) {
			self::emit_identity_event(
				'scim_update',
				array(
					'user_id' => $user->ID,
					'method'  => 'patch',
				)
			);
		}

		return new \WP_REST_Response( self::format_scim_user( $user ), 200 );
	}

	public function delete_user( \WP_REST_Request $request ): \WP_REST_Response {
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

		$scope       = self::DEPROVISION_SCOPE_NETWORK === $request->get_param( 'scope' ) ? self::DEPROVISION_SCOPE_NETWORK : self::DEPROVISION_SCOPE_SITE;
		$external_id = (string) get_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ), true );
		$audit_base  = array_merge(
			self::build_delete_request_context( $request, $scope ),
			array(
				'user_id'     => $user->ID,
				'external_id' => $external_id,
			)
		);

		if ( self::is_protected_account( $user->ID, (array) $user->roles ) ) {
			self::emit_identity_event(
				'scim_delete_rejected',
				array_merge(
					$audit_base,
					array(
						'reason' => 'protected_account',
						'roles'  => array_values( (array) $user->roles ),
					)
				)
			);

			return self::scim_error_response( new \WP_Error(
				'scim_forbidden',
				'Administrator accounts cannot be managed via SCIM.',
				array( 'status' => 403 )
			) );
		}

		if ( self::DEPROVISION_SCOPE_NETWORK === $scope ) {
			if ( ! is_multisite() ) {
				self::emit_identity_event(
					'scim_delete_rejected',
					array_merge(
						$audit_base,
						array(
							'reason' => 'network_scope_requires_multisite',
						)
					)
				);

				return self::scim_error_response( new \WP_Error(
					'scim_bad_request',
					'Network deprovision mode requires WordPress Multisite.',
					array( 'status' => 400 )
				) );
			}

			$network_plan = self::build_network_deprovision_plan( $user->ID );
			if ( ! empty( $network_plan['protected_blogs'] ) ) {
				self::emit_identity_event(
					'scim_delete_rejected',
					array_merge(
						$audit_base,
						array(
							'reason'          => 'protected_network_membership',
							'protected_blogs' => $network_plan['protected_blogs'],
						)
					)
				);

				return self::scim_error_response( new \WP_Error(
					'scim_forbidden',
					'Network deprovision cannot manage administrator memberships.',
					array( 'status' => 403 )
				) );
			}

			if ( ! empty( $network_plan['conflicts'] ) ) {
				self::emit_identity_event(
					'scim_delete_rejected',
					array_merge(
						$audit_base,
						array(
							'reason'           => 'missing_reassignment_target',
							'conflict_blogs'   => $network_plan['conflicts'],
							'blog_operations'  => $network_plan['blog_operations'],
						)
					)
				);

				return self::scim_error_response( new \WP_Error(
					'scim_conflict',
					'Network deprovision requires a valid reassignment target on every site that still has authored content.',
					array( 'status' => 409 )
				) );
			}

			$completed_blog_ids = array();
			foreach ( $network_plan['blog_operations'] as $site_plan ) {
				switch_to_blog( (int) $site_plan['blog_id'] );
				$removed = remove_user_from_blog( $user->ID, (int) $site_plan['blog_id'], (int) $site_plan['reassign_user_id'] );
				if ( is_wp_error( $removed ) ) {
					restore_current_blog();
					self::emit_identity_event(
						'scim_delete_failed',
						array_merge(
							$audit_base,
							array(
								'reason'              => 'remove_user_from_blog_failed',
								'completed_blog_ids'  => $completed_blog_ids,
								'failed_blog_id'      => (int) $site_plan['blog_id'],
								'failed_blog_message' => $removed->get_error_message(),
							)
						)
					);

					return self::scim_error_response( new \WP_Error(
						'scim_internal',
						'Failed to remove user from site ' . (int) $site_plan['blog_id'] . ': ' . $removed->get_error_message(),
						array( 'status' => 500 )
					) );
				}

				self::clear_site_identity_binding( $user->ID, true );
				restore_current_blog();
				$completed_blog_ids[] = (int) $site_plan['blog_id'];
			}

			self::set_network_scim_suspended( $user->ID, true );
			\WP_Session_Tokens::get_instance( $user->ID )->destroy_all();

			self::emit_identity_event(
				'scim_delete',
				array_merge(
					$audit_base,
					array(
						'mode'               => 'remove_from_network',
						'global_suspended'   => true,
						'blog_operations'    => $network_plan['blog_operations'],
						'completed_blog_ids' => $completed_blog_ids,
						'remaining_blog_ids' => self::get_user_blog_ids( $user->ID ),
					)
				)
			);

			return new \WP_REST_Response( null, 204 );
		}

		$site_plan = self::build_current_site_deprovision_plan( $user->ID );
		if ( $site_plan['content_summary']['total'] > 0 && 0 === $site_plan['reassign_user_id'] ) {
			self::emit_identity_event(
				'scim_delete_rejected',
				array_merge(
					$audit_base,
					array(
						'reason'        => 'missing_reassignment_target',
						'site_plan'     => $site_plan,
					)
				)
			);

			return self::scim_error_response( new \WP_Error(
				'scim_conflict',
				'Cannot safely delete this user because no reassignment target is available for authored content on this site.',
				array( 'status' => 409 )
			) );
		}

		if ( is_multisite() ) {
			$removed = remove_user_from_blog( $user->ID, get_current_blog_id(), (int) $site_plan['reassign_user_id'] );
			if ( is_wp_error( $removed ) ) {
				self::emit_identity_event(
					'scim_delete_failed',
					array_merge(
						$audit_base,
						array(
							'reason'              => 'remove_user_from_blog_failed',
							'failed_blog_id'      => get_current_blog_id(),
							'failed_blog_message' => $removed->get_error_message(),
							'site_plan'           => $site_plan,
						)
					)
				);

				return self::scim_error_response( new \WP_Error(
					'scim_internal',
					'Failed to remove user from this site: ' . $removed->get_error_message(),
					array( 'status' => 500 )
				) );
			}

			self::clear_site_identity_binding( $user->ID, true );
			$remaining_blog_ids = self::get_user_blog_ids( $user->ID );
			$global_suspended  = false;
			if ( empty( $remaining_blog_ids ) ) {
				self::set_network_scim_suspended( $user->ID, true );
				$global_suspended = true;
			}

			\WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
			self::emit_identity_event(
				'scim_delete',
				array_merge(
					$audit_base,
					array_merge(
						$site_plan,
						array(
							'mode'               => 'remove_from_blog',
							'global_suspended'   => $global_suspended,
							'remaining_blog_ids' => $remaining_blog_ids,
						)
					)
				)
			);

			return new \WP_REST_Response( null, 204 );
		}

		if ( ! function_exists( 'wp_delete_user' ) ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
		}

		$deleted = wp_delete_user( $user->ID, $site_plan['reassign_user_id'] > 0 ? (int) $site_plan['reassign_user_id'] : null );
		if ( ! $deleted ) {
			self::emit_identity_event(
				'scim_delete_failed',
				array_merge(
					$audit_base,
					array(
						'reason'    => 'wp_delete_user_failed',
						'site_plan' => $site_plan,
					)
				)
			);

			return self::scim_error_response( new \WP_Error(
				'scim_internal',
				'Failed to delete the user.',
				array( 'status' => 500 )
			) );
		}

		self::emit_identity_event(
			'scim_delete',
			array_merge(
				$audit_base,
				array_merge(
					$site_plan,
					array(
						'mode' => 'delete_user',
					)
				)
			)
		);

		return new \WP_REST_Response( null, 204 );
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

	/**
	 * Emit an auditable SCIM identity event.
	 *
	 * @param array<string, mixed> $context
	 */
	private static function emit_identity_event( string $event, array $context = array() ): void {
		do_action(
			'ea_identity_event',
			$event,
			array_merge(
				array(
					'blog_id' => get_current_blog_id(),
					'source'  => 'scim',
				),
				$context
			)
		);
	}

	/**
	 * Build the deletion audit context from the current request.
	 */
	private static function build_delete_request_context( \WP_REST_Request $request, string $scope ): array {
		$forwarded_for = sanitize_text_field( (string) $request->get_header( 'x-forwarded-for' ) );
		$remote_addr   = '';

		if ( '' !== $forwarded_for ) {
			$parts       = explode( ',', $forwarded_for );
			$remote_addr = sanitize_text_field( trim( $parts[0] ) );
		}

		if ( '' === $remote_addr && isset( $_SERVER['REMOTE_ADDR'] ) ) {
			$remote_addr = sanitize_text_field( wp_unslash( (string) $_SERVER['REMOTE_ADDR'] ) );
		}

		$user_agent = sanitize_text_field( substr( (string) $request->get_header( 'user-agent' ), 0, 255 ) );
		$request_id = sanitize_text_field( (string) $request->get_header( 'x-request-id' ) );

		return array_filter(
			array(
				'request_scope'      => $scope,
				'request_route'      => $request->get_route(),
				'request_id'         => $request_id,
				'request_ip'         => $remote_addr,
				'request_user_agent' => $user_agent,
			),
			static fn( $value ): bool => '' !== (string) $value
		);
	}

	/**
	 * Check whether the account is protected from automated SCIM management.
	 *
	 * @param array<int, string> $roles
	 */
	private static function is_protected_account( int $user_id, array $roles ): bool {
		return 1 === $user_id || is_super_admin( $user_id ) || in_array( 'administrator', $roles, true );
	}

	/**
	 * Build the deprovision plan for the current site.
	 *
	 * @return array<string, mixed>
	 */
	private static function build_current_site_deprovision_plan( int $user_id ): array {
		$steward = self::resolve_site_reassignment_target( $user_id );

		return array(
			'blog_id'                    => get_current_blog_id(),
			'reassign_user_id'           => (int) $steward['user_id'],
			'steward_source'             => $steward['source'],
			'configured_steward_user_id' => (int) $steward['configured_user_id'],
			'steward_resolution_reason'  => $steward['reason'],
			'content_summary'            => self::get_authored_content_summary( $user_id ),
		);
	}

	/**
	 * Build a fail-closed network deprovision plan across every site membership.
	 *
	 * @return array<string, mixed>
	 */
	private static function build_network_deprovision_plan( int $user_id ): array {
		$plan = array(
			'blog_operations' => array(),
			'conflicts'       => array(),
			'protected_blogs' => array(),
		);

		foreach ( self::get_user_blog_ids( $user_id ) as $blog_id ) {
			switch_to_blog( $blog_id );
			$blog_user = get_user_by( 'id', $user_id );

			if ( ! ( $blog_user instanceof \WP_User ) ) {
				restore_current_blog();
				continue;
			}

			if ( self::is_protected_account( $blog_user->ID, (array) $blog_user->roles ) ) {
				$plan['protected_blogs'][] = array(
					'blog_id' => $blog_id,
					'roles'   => array_values( (array) $blog_user->roles ),
				);
				restore_current_blog();
				continue;
			}

			$site_plan          = self::build_current_site_deprovision_plan( $user_id );
			$site_plan['roles'] = array_values( (array) $blog_user->roles );

			if ( $site_plan['content_summary']['total'] > 0 && 0 === $site_plan['reassign_user_id'] ) {
				$plan['conflicts'][] = array(
					'blog_id'                    => $blog_id,
					'content_summary'            => $site_plan['content_summary'],
					'steward_source'             => $site_plan['steward_source'],
					'configured_steward_user_id' => $site_plan['configured_steward_user_id'],
					'steward_resolution_reason'  => $site_plan['steward_resolution_reason'],
				);
				restore_current_blog();
				continue;
			}

			$plan['blog_operations'][] = $site_plan;
			restore_current_blog();
		}

		return $plan;
	}

	/**
	 * Resolve the site's content steward or deterministic administrator fallback.
	 *
	 * @return array<string, mixed>
	 */
	private static function resolve_site_reassignment_target( int $excluded_user_id ): array {
		$configured_user_id = SettingsController::read_raw_deprovision_steward_user_id();

		if ( $configured_user_id > 0 ) {
			if ( self::is_valid_steward_user( $configured_user_id, $excluded_user_id ) ) {
				return array(
					'user_id'            => $configured_user_id,
					'source'             => 'configured_steward',
					'configured_user_id' => $configured_user_id,
					'reason'             => 'Configured steward resolved for this site.',
				);
			}

			return array(
				'user_id'            => 0,
				'source'             => 'configured_invalid',
				'configured_user_id' => $configured_user_id,
				'reason'             => 'Configured steward is not eligible for this site.',
			);
		}

		$fallback_user_id = self::find_fallback_site_administrator( $excluded_user_id );
		if ( $fallback_user_id > 0 ) {
			return array(
				'user_id'            => $fallback_user_id,
				'source'             => 'fallback_administrator',
				'configured_user_id' => 0,
				'reason'             => 'Deterministic site administrator fallback resolved.',
			);
		}

		return array(
			'user_id'            => 0,
			'source'             => 'none',
			'configured_user_id' => 0,
			'reason'             => 'No eligible steward is configured and no deterministic administrator fallback is available.',
		);
	}

	/**
	 * Check whether a candidate steward is valid on the current site.
	 */
	private static function is_valid_steward_user( int $candidate_user_id, int $excluded_user_id ): bool {
		if ( $candidate_user_id <= 0 || $candidate_user_id === $excluded_user_id ) {
			return false;
		}

		if ( 1 === $candidate_user_id || is_super_admin( $candidate_user_id ) ) {
			return false;
		}

		$candidate = get_userdata( $candidate_user_id );
		if ( ! ( $candidate instanceof \WP_User ) ) {
			return false;
		}

		if ( is_multisite() && ! is_user_member_of_blog( $candidate_user_id, get_current_blog_id() ) ) {
			return false;
		}

		return user_can( $candidate, 'edit_posts' );
	}

	/**
	 * Resolve the deterministic administrator fallback for the current site.
	 */
	private static function find_fallback_site_administrator( int $excluded_user_id ): int {
		$args = array(
			'fields'  => 'ids',
			'exclude' => array( $excluded_user_id ),
			'role'    => 'administrator',
			'orderby' => 'ID',
			'order'   => 'ASC',
		);

		if ( is_multisite() ) {
			$args['blog_id'] = get_current_blog_id();
		}

		$administrators = get_users( $args );
		foreach ( $administrators as $administrator_id ) {
			$administrator_id = (int) $administrator_id;
			if ( 1 === $administrator_id || is_super_admin( $administrator_id ) ) {
				continue;
			}

			return $administrator_id;
		}

		return 0;
	}

	/**
	 * Summarise authored content on the current site for reassignment planning.
	 *
	 * @return array<string, int>
	 */
	private static function get_authored_content_summary( int $user_id ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$posts = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(1) FROM {$wpdb->posts} WHERE post_author = %d", $user_id )
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$links = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(1) FROM {$wpdb->links} WHERE link_owner = %d", $user_id )
		);

		return array(
			'posts' => $posts,
			'links' => $links,
			'total' => $posts + $links,
		);
	}

	/**
	 * List the site memberships for a user.
	 *
	 * @return array<int, int>
	 */
	private static function get_user_blog_ids( int $user_id ): array {
		if ( ! is_multisite() ) {
			return array( get_current_blog_id() );
		}

		$blog_ids = array();
		foreach ( get_blogs_of_user( $user_id ) as $blog ) {
			$blog_id = isset( $blog->userblog_id ) ? (int) $blog->userblog_id : (int) ( $blog->blog_id ?? 0 );
			if ( $blog_id > 0 ) {
				$blog_ids[] = $blog_id;
			}
		}

		sort( $blog_ids );

		return array_values( array_unique( $blog_ids ) );
	}

	/**
	 * Set or clear the network-wide suspension flag.
	 */
	private static function set_network_scim_suspended( int $user_id, bool $suspended ): void {
		if ( $suspended ) {
			update_user_meta( $user_id, SiteMetaKeys::NETWORK_SCIM_SUSPENDED, 'true' );
			return;
		}

		delete_user_meta( $user_id, SiteMetaKeys::NETWORK_SCIM_SUSPENDED );
	}

	/**
	 * Clear the current site's identity binding for a deprovisioned user.
	 */
	private static function clear_site_identity_binding( int $user_id, bool $keep_suspended ): void {
		delete_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ) );
		delete_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SCIM_ID ) );
		delete_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::IDP_UID ) );
		delete_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::IDP_ISSUER ) );
		delete_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SSO_LOGIN_AT ) );
		delete_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SESSION_EXPIRES ) );

		if ( $keep_suspended ) {
			update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ), 'true' );
			return;
		}

		delete_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SCIM_SUSPENDED ) );
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
