<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\CredentialRepository;
use EnterpriseAuth\Plugin\WebAuthnHelper;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * REST controller for the WebAuthn authentication (login) ceremony.
 *
 * GET  /enterprise-auth/v1/passkeys/login – return request options (challenge)
 * POST /enterprise-auth/v1/passkeys/login – verify assertion & log user in
 */
final class PasskeyLoginController {

	private const NAMESPACE     = 'enterprise-auth/v1';
	private const ROUTE         = '/passkeys/login';
	private const TRANSIENT     = 'ea_webauthn_login_';
	private const CHALLENGE_TTL = 60; // seconds

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			self::ROUTE,
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_request_options' ),
					'permission_callback' => '__return_true', // public – login page
					'args'                => array(
						'email' => array(
							'type'              => 'string',
							'required'          => false,
							'sanitize_callback' => 'sanitize_email',
						),
					),
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'verify_assertion' ),
					'permission_callback' => '__return_true', // public – login page
				),
			)
		);
	}

	/**
	 * GET – generate authentication challenge.
	 *
	 * If ?email is provided, only allow credentials for that user.
	 * Otherwise, use discoverable / resident credentials.
	 */
	public function get_request_options( \WP_REST_Request $request ): \WP_REST_Response {
		$email     = $request->get_param( 'email' );
		$challenge = WebAuthnHelper::generate_challenge();

		$allow_credentials = array();
		$user_id           = 0;

		if ( $email ) {
			$user = get_user_by( 'email', $email );
			if ( ! $user ) {
				// Return a valid challenge anyway to avoid user-enumeration timing attacks.
				// No allowCredentials means the browser will fail gracefully.
				$user_id = 0;
			} else {
				$user_id           = (int) $user->ID;
				$sources           = CredentialRepository::find_all_for_user( $user_id );
				$allow_credentials = array_map(
					static fn( $src ) => $src->getPublicKeyCredentialDescriptor(),
					$sources
				);
			}
		}

		$options = PublicKeyCredentialRequestOptions::create(
			challenge: $challenge,
			rpId: WebAuthnHelper::rp_id(),
			allowCredentials: $allow_credentials,
			userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
			timeout: 60000,
		);

		// Keyed by a random nonce so we can look it up on POST.
		$session_key = bin2hex( random_bytes( 16 ) );
		set_transient(
			self::transient_key( $session_key ),
			wp_json_encode(
				array(
					'options' => WebAuthnHelper::serializer()->serialize( $options, 'json' ),
					'user_id' => $user_id,
				)
			),
			self::CHALLENGE_TTL
		);

		$json                = WebAuthnHelper::serializer()->serialize( $options, 'json' );
		$data                = json_decode( $json, true );
		$data['session_key'] = $session_key;

		return new \WP_REST_Response( $data, 200 );
	}

	/**
	 * POST – verify the assertion and log the user in.
	 */
	public function verify_assertion( \WP_REST_Request $request ): \WP_REST_Response {
		$body        = json_decode( $request->get_body(), true );
		$session_key = sanitize_text_field( $body['session_key'] ?? '' );

		if ( ! $session_key ) {
			return new \WP_REST_Response( array( 'error' => 'Missing session key.' ), 400 );
		}

		$stored_raw = get_transient( self::transient_key( $session_key ) );
		delete_transient( self::transient_key( $session_key ) );

		if ( ! $stored_raw ) {
			return new \WP_REST_Response( array( 'error' => 'Challenge expired or not found.' ), 400 );
		}

		$stored     = json_decode( $stored_raw, true );
		$serializer = WebAuthnHelper::serializer();

		/** @var PublicKeyCredentialRequestOptions $request_options */
		$request_options = $serializer->deserialize(
			$stored['options'],
			PublicKeyCredentialRequestOptions::class,
			'json'
		);

		// Remove session_key from the body before deserialization.
		unset( $body['session_key'] );
		$credential_json = wp_json_encode( $body );

		try {
			/** @var PublicKeyCredential $pkc */
			$pkc = $serializer->deserialize( $credential_json, PublicKeyCredential::class, 'json' );
		} catch ( \Throwable $e ) {
			return new \WP_REST_Response( array( 'error' => 'Invalid assertion payload.' ), 400 );
		}

		$response = $pkc->response;
		if ( ! $response instanceof AuthenticatorAssertionResponse ) {
			return new \WP_REST_Response( array( 'error' => 'Expected an assertion response.' ), 400 );
		}

		// Look up the stored credential by credential ID.
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		$credential_source = CredentialRepository::find_by_credential_id( $pkc->rawId );
		if ( ! $credential_source ) {
			return new \WP_REST_Response( array( 'error' => 'Credential not found.' ), 400 );
		}

		// Determine user handle.
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		$user_handle = $credential_source->userHandle;

		try {
			$updated_source = WebAuthnHelper::assertion_validator()->check(
				$credential_source,
				$response,
				$request_options,
				WebAuthnHelper::rp_id(),
				$user_handle,
			);
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Enterprise IAM – Passkey login error: ' . $e->getMessage() );
			}
			return new \WP_REST_Response(
				array( 'error' => 'Passkey login failed. Please try again.' ),
				400
			);
		}

		// Update sign count for clone detection.
		CredentialRepository::update_counter(
			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			$updated_source->publicKeyCredentialId,
			$updated_source->counter
		);

		// Resolve the WP user from the credential's user_handle (which is the hash of user_id).
		// We need to look up by finding which user matches.
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		$wp_user_id = $this->resolve_user_id( $updated_source->userHandle );
		if ( ! $wp_user_id ) {
			return new \WP_REST_Response( array( 'error' => 'User not found.' ), 400 );
		}

		// Log the user in (session cookie, not persistent "remember me").
		wp_set_auth_cookie( $wp_user_id, false, is_ssl() );
		do_action( 'wp_login', get_userdata( $wp_user_id )->user_login, get_userdata( $wp_user_id ) );

		return new \WP_REST_Response(
			array(
				'success'     => true,
				'redirect_to' => admin_url(),
			),
			200
		);
	}

	/**
	 * Resolve WP user_id from the userHandle stored during registration.
	 *
	 * During registration, userHandle = hash('sha256', user_id, true).
	 * We look through the credentials table to find the matching user_id.
	 */
	private function resolve_user_id( string $user_handle ): int {
		global $wpdb;

		$table = \EnterpriseAuth\Plugin\DatabaseManager::table_name();

		// More reliable: iterate known IDs from our table and match handle.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$user_ids = $wpdb->get_col( "SELECT DISTINCT user_id FROM {$table}" );

		foreach ( $user_ids as $uid ) {
			$expected = hash( 'sha256', (string) $uid, true );
			if ( hash_equals( $expected, $user_handle ) ) {
				return (int) $uid;
			}
		}

		return 0;
	}

	/**
	 * Blog-scoped transient key for WebAuthn login challenges.
	 */
	private static function transient_key( string $session_key ): string {
		$key = self::TRANSIENT . sanitize_text_field( $session_key );

		if ( ! is_multisite() ) {
			return $key;
		}

		return 'ea_' . get_current_blog_id() . '_' . $key;
	}
}
