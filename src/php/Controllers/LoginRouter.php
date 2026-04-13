<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\FederationFlowGuard;
use EnterpriseAuth\Plugin\IdpManager;
use EnterpriseAuth\Plugin\SiteMetaKeys;

/**
 * Intelligent Domain Routing.
 *
 * Accepts an email address, extracts the domain, and issues a short-lived,
 * browser-bound continuation URL. The continuation flow resolves to either
 * SSO or local (Passkey/password) authentication without exposing that
 * distinction directly in the API response.
 *
 * Routes:
 *   POST /enterprise-auth/v1/route-login
 *   GET  /enterprise-auth/v1/route-login/continue?flow={key}
 *   GET  /enterprise-auth/v1/route-login/local-options?flow={key}
 */
final class LoginRouter {

	private const NAMESPACE        = 'enterprise-auth/v1';
	private const ROUTE_RATE_LIMIT = 30;
	private const ROUTE_FLOW_TTL   = 120;
	private const FLOW_PROTOCOL    = 'login_route';
	private const LOCAL_PROTOCOL   = 'login_local';
	private const LOCAL_FLOW_QUERY = 'ea_local_flow';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/route-login',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'route' ),
				'permission_callback' => '__return_true',
				'args'                => array(
					'email' => array(
						'type'              => 'string',
						'required'          => true,
						'sanitize_callback' => 'sanitize_email',
					),
					'redirect_to' => array(
						'type'     => 'string',
						'required' => false,
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/route-login/continue',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'continue_login' ),
				'permission_callback' => '__return_true',
				'args'                => array(
					'flow' => array(
						'type'              => 'string',
						'required'          => true,
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/route-login/local-options',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'local_options' ),
				'permission_callback' => '__return_true',
				'args'                => array(
					'flow' => array(
						'type'              => 'string',
						'required'          => true,
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);
	}

	/**
	 * Issue a continuation URL for the given email address.
	 */
	public function route( \WP_REST_Request $request ): \WP_REST_Response {
		$rate_error = $this->check_rate_limit( $request );
		if ( is_wp_error( $rate_error ) ) {
			$status = (int) ( $rate_error->get_error_data()['status'] ?? 429 );

			return new \WP_REST_Response(
				array( 'error' => $rate_error->get_error_message() ),
				$status
			);
		}

		$email = $request->get_param( 'email' );
		if ( ! is_email( $email ) ) {
			return new \WP_REST_Response( array( 'error' => 'Invalid email address.' ), 400 );
		}

		$redirect_to = $this->validated_redirect_target( (string) $request->get_param( 'redirect_to' ) );
		$outcome     = $this->resolve_login_outcome( (string) $email, $redirect_to );

		try {
			$flow_key = bin2hex( random_bytes( 16 ) );
		} catch ( \Throwable $e ) {
			return new \WP_REST_Response( array( 'error' => 'Could not continue login. Please try again.' ), 500 );
		}

		$issued = FederationFlowGuard::issue( self::FLOW_PROTOCOL, $flow_key, $outcome, self::ROUTE_FLOW_TTL );
		if ( is_wp_error( $issued ) ) {
			return new \WP_REST_Response( array( 'error' => 'Could not continue login. Please try again.' ), 500 );
		}

		$continue_url = add_query_arg(
			array(
				'flow' => $flow_key,
			),
			rest_url( self::NAMESPACE . '/route-login/continue' )
		);

		return new \WP_REST_Response(
			array(
				'redirect_url' => $continue_url,
			),
			200
		);
	}

	/**
	 * Continue the browser-bound login route flow.
	 */
	public function continue_login( \WP_REST_Request $request ): \WP_REST_Response {
		$flow_key  = sanitize_text_field( (string) $request->get_param( 'flow' ) );
		$flow_data = FederationFlowGuard::consume( self::FLOW_PROTOCOL, $flow_key );

		if ( is_wp_error( $flow_data ) ) {
			return $this->redirect_response( wp_login_url() );
		}

		$outcome = sanitize_key( (string) ( $flow_data['outcome'] ?? '' ) );
		if ( 'sso' === $outcome ) {
			$redirect_url = (string) ( $flow_data['redirect_url'] ?? '' );
			if ( '' === $redirect_url ) {
				return $this->redirect_response( wp_login_url() );
			}

			return $this->redirect_response( $redirect_url );
		}

		if ( 'local' !== $outcome ) {
			return $this->redirect_response( wp_login_url() );
		}

		$email = sanitize_email( (string) ( $flow_data['email'] ?? '' ) );
		if ( ! is_email( $email ) ) {
			return $this->redirect_response( wp_login_url() );
		}

		try {
			$local_flow_key = bin2hex( random_bytes( 16 ) );
		} catch ( \Throwable $e ) {
			return $this->redirect_response( wp_login_url() );
		}

		$issued = FederationFlowGuard::issue(
			self::LOCAL_PROTOCOL,
			$local_flow_key,
			array(
				'email' => $email,
			),
			self::ROUTE_FLOW_TTL
		);

		if ( is_wp_error( $issued ) ) {
			return $this->redirect_response( wp_login_url() );
		}

		$login_url = add_query_arg(
			array(
				self::LOCAL_FLOW_QUERY => $local_flow_key,
			),
			wp_login_url()
		);

		$redirect_to = $this->validated_redirect_target( (string) ( $flow_data['redirect_to'] ?? '' ) );
		if ( '' !== $redirect_to ) {
			$login_url = add_query_arg( 'redirect_to', $redirect_to, $login_url );
		}

		return $this->redirect_response( $login_url );
	}

	/**
	 * Resolve a local continuation flow into the email value shown in the browser.
	 */
	public function local_options( \WP_REST_Request $request ): \WP_REST_Response {
		$flow_key  = sanitize_text_field( (string) $request->get_param( 'flow' ) );
		$flow_data = FederationFlowGuard::consume( self::LOCAL_PROTOCOL, $flow_key );

		if ( is_wp_error( $flow_data ) ) {
			return new \WP_REST_Response(
				array( 'error' => 'Login step expired. Please enter your email again.' ),
				400
			);
		}

		$email = sanitize_email( (string) ( $flow_data['email'] ?? '' ) );
		if ( ! is_email( $email ) ) {
			return new \WP_REST_Response(
				array( 'error' => 'Login step expired. Please enter your email again.' ),
				400
			);
		}

		return new \WP_REST_Response(
			array(
				'email' => $email,
			),
			200
		);
	}

	/**
	 * Determine the login outcome for the given email address.
	 *
	 * @return array<string, string>
	 */
	private function resolve_login_outcome( string $email, string $redirect_to ): array {
		$parts  = explode( '@', $email );
		$domain = strtolower( $parts[1] ?? '' );

		$idp = IdpManager::find_by_domain( $domain );
		if ( ! $idp ) {
			return array(
				'outcome'     => 'local',
				'email'       => $email,
				'redirect_to' => $redirect_to,
			);
		}

		// Even when a domain is mapped to an IdP, a WordPress account that
		// has no SSO provider binding is a local account and must log in
		// locally (password / passkey). This preserves break-glass admin
		// access and any other intentionally-local accounts on SSO domains.
		$wp_user = get_user_by( 'email', $email );

		// Multisite: ignore users not on this site — they'll be JIT provisioned via SSO.
		if ( is_multisite() && $wp_user && ! is_user_member_of_blog( $wp_user->ID, get_current_blog_id() ) ) {
			$wp_user = null;
		}

		if ( $wp_user ) {
			$existing_provider = get_user_meta( $wp_user->ID, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ), true );
			if ( empty( $existing_provider ) ) {
				return array(
					'outcome'     => 'local',
					'email'       => $email,
					'redirect_to' => $redirect_to,
				);
			}
		}

		return array(
			'outcome'      => 'sso',
			'redirect_url' => $this->build_redirect_url( $idp ),
			'redirect_to'  => $redirect_to,
		);
	}

	/**
	 * Build the SSO initiation redirect URL.
	 */
	private function build_redirect_url( array $idp ): string {
		if ( ( $idp['protocol'] ?? '' ) === 'oidc' ) {
			// Route to the dedicated OIDC Login Controller which handles
			// state/nonce generation and the Authorization Code redirect.
			return add_query_arg(
				array(
					'idp_id' => $idp['id'],
				),
				rest_url( 'enterprise-auth/v1/oidc/login' )
			);
		}

		// SAML – redirect to our SP-initiated login endpoint which
		// builds the AuthnRequest via the OneLogin toolkit.
		return add_query_arg(
			array(
				'idp_id' => $idp['id'],
			),
			rest_url( 'enterprise-auth/v1/saml/login' )
		);
	}

	/**
	 * Apply a low-cost per-client rate limit to the public routing endpoint.
	 */
	private function check_rate_limit( \WP_REST_Request $request ): ?\WP_Error {
		$client_id = $this->client_rate_limit_key( $request );
		$window    = (string) intdiv( time(), 60 );
		$key       = 'ea_route_rate_' . md5( $client_id . ':' . $window );
		$count     = (int) get_transient( $key );

		++$count;
		set_transient( $key, $count, 120 );

		if ( $count > self::ROUTE_RATE_LIMIT ) {
			return new \WP_Error(
				'ea_route_login_rate_limited',
				'Too many login routing attempts. Please wait a minute and try again.',
				array( 'status' => 429 )
			);
		}

		return null;
	}

	/**
	 * Derive a coarse client key for public route-login throttling.
	 */
	private function client_rate_limit_key( \WP_REST_Request $request ): string {
		$forwarded_for = sanitize_text_field( (string) $request->get_header( 'x-forwarded-for' ) );
		if ( '' !== $forwarded_for ) {
			$parts = explode( ',', $forwarded_for );
			if ( ! empty( $parts[0] ) ) {
				return trim( (string) $parts[0] );
			}
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$remote_addr = $_SERVER['REMOTE_ADDR'] ?? '';

		return is_string( $remote_addr ) && '' !== $remote_addr
			? sanitize_text_field( $remote_addr )
			: 'unknown';
	}

	/**
	 * Validate a redirect target before reusing it in the login continuation flow.
	 */
	private function validated_redirect_target( string $redirect_to ): string {
		$redirect_to = trim( $redirect_to );
		if ( '' === $redirect_to ) {
			return '';
		}

		$validated = wp_validate_redirect( $redirect_to, '' );

		return is_string( $validated ) ? $validated : '';
	}

	/**
	 * Return a REST redirect response.
	 */
	private function redirect_response( string $url ): \WP_REST_Response {
		return new \WP_REST_Response( null, 302, array( 'Location' => $url ) );
	}
}
