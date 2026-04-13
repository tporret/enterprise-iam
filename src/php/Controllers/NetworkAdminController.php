<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\IdpManager;
use EnterpriseAuth\Plugin\IdpView;
use EnterpriseAuth\Plugin\NetworkIdpManager;
use EnterpriseAuth\Plugin\NetworkMode;
use EnterpriseAuth\Plugin\SiteAssignmentManager;

final class NetworkAdminController {

	private const NAMESPACE = 'enterprise-auth/v1';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/network/idps',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'list_idps' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'save_idp' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/network/idps/(?P<id>[a-f0-9-]+)',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_idp' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
				array(
					'methods'             => \WP_REST_Server::DELETABLE,
					'callback'            => array( $this, 'delete_idp' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/network/sites',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'list_sites' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/network/sites/(?P<blog_id>\d+)/assignments',
			array(
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'save_site_assignments' ),
					'permission_callback' => array( $this, 'check_permission' ),
				),
			)
		);
	}

	public function check_permission(): bool {
		return NetworkMode::is_network_mode() && current_user_can( 'manage_network_options' );
	}

	public function list_idps(): \WP_REST_Response {
		$idps = array_map(
			fn( array $idp ): array => IdpView::summary(
				$idp,
				array(
					'assignment_count'   => SiteAssignmentManager::count_sites_for_idp( (string) ( $idp['id'] ?? '' ) ),
					'managed_by_network' => true,
				)
			),
			NetworkIdpManager::all()
		);

		return new \WP_REST_Response( array_values( $idps ), 200 );
	}

	public function get_idp( \WP_REST_Request $request ): \WP_REST_Response {
		$idp = NetworkIdpManager::find( sanitize_text_field( (string) $request->get_param( 'id' ) ) );

		if ( ! $idp ) {
			return new \WP_REST_Response( array( 'error' => 'IdP not found.' ), 404 );
		}

		return new \WP_REST_Response(
			IdpView::detail(
				$idp,
				array(
					'assignment_count'   => SiteAssignmentManager::count_sites_for_idp( (string) ( $idp['id'] ?? '' ) ),
					'managed_by_network' => true,
				)
			),
			200
		);
	}

	public function save_idp( \WP_REST_Request $request ): \WP_REST_Response {
		$raw = $request->get_json_params();

		if ( empty( $raw ) || ! is_array( $raw ) ) {
			return new \WP_REST_Response( array( 'error' => 'Invalid payload.' ), 400 );
		}

		if (
			! empty( $raw['id'] )
			&& ( ! isset( $raw['client_secret'] ) || '••••••••' === $raw['client_secret'] || '' === $raw['client_secret'] )
		) {
			$existing = NetworkIdpManager::find( sanitize_text_field( (string) $raw['id'] ) );
			if ( $existing ) {
				$raw['client_secret'] = $existing['client_secret'] ?? '';
			}
		}

		$sanitized = IdpManager::sanitize( $raw );
		if ( is_wp_error( $sanitized ) ) {
			$status = $sanitized->get_error_data( 'enterprise_auth_invalid_idp_url' );
			$status = is_array( $status ) && isset( $status['status'] ) ? (int) $status['status'] : 400;

			return new \WP_REST_Response(
				array( 'error' => $sanitized->get_error_message() ),
				$status
			);
		}

		$result = NetworkIdpManager::save( $sanitized );
		if ( is_wp_error( $result ) ) {
			$status = $result->get_error_data( 'enterprise_auth_secret_storage_failed' );
			$status = is_array( $status ) && isset( $status['status'] ) ? (int) $status['status'] : 500;

			return new \WP_REST_Response(
				array( 'error' => $result->get_error_message() ),
				$status
			);
		}

		return new \WP_REST_Response(
			IdpView::detail(
				$sanitized,
				array(
					'assignment_count'   => SiteAssignmentManager::count_sites_for_idp( (string) ( $sanitized['id'] ?? '' ) ),
					'managed_by_network' => true,
				)
			),
			200
		);
	}

	public function delete_idp( \WP_REST_Request $request ): \WP_REST_Response {
		$id      = sanitize_text_field( (string) $request->get_param( 'id' ) );
		$deleted = NetworkIdpManager::delete( $id );

		if ( ! $deleted ) {
			return new \WP_REST_Response( array( 'error' => 'IdP not found.' ), 404 );
		}

		SiteAssignmentManager::remove_idp_references( $id );

		return new \WP_REST_Response( array( 'deleted' => true ), 200 );
	}

	public function list_sites(): \WP_REST_Response {
		$network_idps = array();
		foreach ( NetworkIdpManager::all() as $idp ) {
			$network_idps[ (string) ( $idp['id'] ?? '' ) ] = $idp;
		}

		$sites = array();
		foreach ( get_sites( array( 'number' => 0 ) ) as $site ) {
			$blog_id    = (int) $site->blog_id;
			$assignment = SiteAssignmentManager::read_for_blog( $blog_id );
			$providers  = array();

			foreach ( $assignment['assigned_idp_ids'] as $idp_id ) {
				if ( isset( $network_idps[ $idp_id ] ) ) {
					$providers[] = array(
						'id'            => $idp_id,
						'provider_name' => sanitize_text_field( (string) ( $network_idps[ $idp_id ]['provider_name'] ?? '' ) ),
						'protocol'      => sanitize_key( (string) ( $network_idps[ $idp_id ]['protocol'] ?? '' ) ),
					);
				}
			}

			$sites[] = array(
				'blog_id'          => $blog_id,
				'name'             => sanitize_text_field( (string) get_blog_option( $blog_id, 'blogname', '' ) ),
				'url'              => esc_url_raw( get_home_url( $blog_id, '/' ) ),
				'dashboard_url'    => esc_url_raw( get_admin_url( $blog_id, 'admin.php?page=enterprise-auth' ) ),
				'assigned_idp_ids' => $assignment['assigned_idp_ids'],
				'primary_idp_id'   => $assignment['primary_idp_id'],
				'assigned_idps'    => $providers,
			);
		}

		return new \WP_REST_Response( $sites, 200 );
	}

	public function save_site_assignments( \WP_REST_Request $request ): \WP_REST_Response {
		$blog_id = (int) $request->get_param( 'blog_id' );
		$params  = $request->get_json_params();

		if ( $blog_id <= 0 || ! get_site( $blog_id ) ) {
			return new \WP_REST_Response( array( 'error' => 'Site not found.' ), 404 );
		}

		if ( ! is_array( $params ) ) {
			$params = array();
		}

		$assignment = SiteAssignmentManager::save_for_blog( $blog_id, $params );

		return new \WP_REST_Response(
			array(
				'blog_id'          => $blog_id,
				'assigned_idp_ids' => $assignment['assigned_idp_ids'],
				'primary_idp_id'   => $assignment['primary_idp_id'],
			),
			200
		);
	}
}