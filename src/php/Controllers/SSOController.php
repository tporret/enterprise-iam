<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\IdpManager;

/**
 * SSO Callback / Assertion Consumer Service controller.
 *
 * Handles the return leg of both OIDC and SAML flows, verifies tokens/assertions,
 * performs JIT user provisioning, maps roles, and logs the user in.
 *
 * Route: GET /enterprise-auth/v1/sso/callback
 */
final class SSOController {

	private const NAMESPACE = 'enterprise-auth/v1';

	public function register_routes(): void {
		// OIDC callback (code + state arrive as query params).
		register_rest_route( self::NAMESPACE, '/sso/callback', [
			'methods'             => \WP_REST_Server::READABLE,
			'callback'            => [ $this, 'handle_oidc_callback' ],
			'permission_callback' => '__return_true',
		] );

		// SAML ACS (POST with SAMLResponse).
		register_rest_route( self::NAMESPACE, '/sso/acs', [
			'methods'             => \WP_REST_Server::CREATABLE,
			'callback'            => [ $this, 'handle_saml_acs' ],
			'permission_callback' => '__return_true',
		] );
	}

	// ── OIDC ────────────────────────────────────────────────────────────────

	/**
	 * Handle the OIDC authorization code callback.
	 */
	public function handle_oidc_callback( \WP_REST_Request $request ): \WP_REST_Response {
		$code  = $request->get_param( 'code' );
		$state = $request->get_param( 'state' );

		if ( empty( $code ) || empty( $state ) ) {
			return $this->error_redirect( 'Missing authorization code or state.' );
		}

		// Validate the state against our stored transient (CSRF protection).
		$transient_key = 'ea_sso_state_' . sanitize_text_field( $state );
		$state_raw     = get_transient( $transient_key );
		delete_transient( $transient_key );

		if ( ! $state_raw ) {
			return $this->error_redirect( 'Invalid or expired SSO state. Please try again.' );
		}

		$state_data = json_decode( $state_raw, true );
		$idp_id     = $state_data['idp_id'] ?? '';
		$idp        = IdpManager::find( $idp_id );

		if ( ! $idp ) {
			return $this->error_redirect( 'Identity Provider not found.' );
		}

		// Exchange the authorization code for tokens.
		$token_response = $this->exchange_oidc_code( $idp, $code );

		if ( is_wp_error( $token_response ) ) {
			return $this->error_redirect( $token_response->get_error_message() );
		}

		// Verify the ID token and extract claims.
		$claims = $this->extract_oidc_claims( $idp, $token_response );

		if ( is_wp_error( $claims ) ) {
			return $this->error_redirect( $claims->get_error_message() );
		}

		// JIT provisioning and login.
		$result = $this->provision_and_login( $idp, $claims );

		if ( is_wp_error( $result ) ) {
			return $this->error_redirect( $result->get_error_message() );
		}

		return $this->success_redirect();
	}

	/**
	 * Exchange authorization code for OIDC tokens.
	 *
	 * @return array|\WP_Error
	 */
	private function exchange_oidc_code( array $idp, string $code ) {
		$token_endpoint = $idp['token_endpoint'] ?? '';

		if ( empty( $token_endpoint ) ) {
			return new \WP_Error( 'sso_error', 'Token endpoint not configured for this IdP.' );
		}

		$response = wp_remote_post( $token_endpoint, [
			'body'    => [
				'grant_type'    => 'authorization_code',
				'code'          => $code,
				'redirect_uri'  => rest_url( 'enterprise-auth/v1/sso/callback' ),
				'client_id'     => $idp['client_id'] ?? '',
				'client_secret' => $idp['client_secret'] ?? '',
			],
			'timeout' => 30,
		] );

		if ( is_wp_error( $response ) ) {
			return new \WP_Error( 'sso_error', 'Failed to contact token endpoint: ' . $response->get_error_message() );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! empty( $body['error'] ) ) {
			return new \WP_Error( 'sso_error', 'Token error: ' . ( $body['error_description'] ?? $body['error'] ) );
		}

		if ( empty( $body['id_token'] ) ) {
			return new \WP_Error( 'sso_error', 'No ID token received from the identity provider.' );
		}

		return $body;
	}

	/**
	 * Decode and verify the OIDC ID token, return user claims.
	 *
	 * @return array|\WP_Error  Array with 'email', 'name', 'groups' keys.
	 */
	private function extract_oidc_claims( array $idp, array $token_response ) {
		$id_token = $token_response['id_token'];
		$parts    = explode( '.', $id_token );

		if ( count( $parts ) !== 3 ) {
			return new \WP_Error( 'sso_error', 'Malformed ID token.' );
		}

		// Decode payload (we rely on the token endpoint TLS + client_secret for verification).
		$payload = json_decode( $this->base64url_decode( $parts[1] ), true );

		if ( ! $payload || empty( $payload['email'] ) ) {
			return new \WP_Error( 'sso_error', 'ID token missing required email claim.' );
		}

		// Verify audience.
		$expected_aud = $idp['client_id'] ?? '';
		$aud          = $payload['aud'] ?? '';

		if ( is_array( $aud ) ) {
			if ( ! in_array( $expected_aud, $aud, true ) ) {
				return new \WP_Error( 'sso_error', 'ID token audience mismatch.' );
			}
		} elseif ( $aud !== $expected_aud ) {
			return new \WP_Error( 'sso_error', 'ID token audience mismatch.' );
		}

		// Verify expiration.
		if ( isset( $payload['exp'] ) && $payload['exp'] < time() ) {
			return new \WP_Error( 'sso_error', 'ID token has expired.' );
		}

		// Optionally fetch userinfo for additional claims.
		$userinfo_endpoint = $idp['userinfo_endpoint'] ?? '';
		$access_token      = $token_response['access_token'] ?? '';

		if ( $userinfo_endpoint && $access_token ) {
			$userinfo = $this->fetch_userinfo( $userinfo_endpoint, $access_token );
			if ( ! is_wp_error( $userinfo ) ) {
				$payload = array_merge( $payload, $userinfo );
			}
		}

		return [
			'email'  => sanitize_email( $payload['email'] ),
			'name'   => sanitize_text_field( $payload['name'] ?? '' ),
			'groups' => array_map( 'sanitize_text_field', (array) ( $payload['groups'] ?? [] ) ),
		];
	}

	/**
	 * Fetch the OIDC userinfo endpoint.
	 *
	 * @return array|\WP_Error
	 */
	private function fetch_userinfo( string $endpoint, string $access_token ) {
		$response = wp_remote_get( $endpoint, [
			'headers' => [ 'Authorization' => 'Bearer ' . $access_token ],
			'timeout' => 15,
		] );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		return is_array( $body ) ? $body : new \WP_Error( 'sso_error', 'Invalid userinfo response.' );
	}

	// ── SAML ────────────────────────────────────────────────────────────────

	/**
	 * Handle the SAML Assertion Consumer Service (ACS) POST.
	 */
	public function handle_saml_acs( \WP_REST_Request $request ): \WP_REST_Response {
		$saml_response_b64 = $request->get_param( 'SAMLResponse' );
		$relay_state       = $request->get_param( 'RelayState' );

		if ( empty( $saml_response_b64 ) ) {
			return $this->error_redirect( 'Missing SAML response.' );
		}

		// Validate RelayState (CSRF protection).
		$transient_key = 'ea_sso_state_' . sanitize_text_field( $relay_state ?? '' );
		$state_raw     = get_transient( $transient_key );
		delete_transient( $transient_key );

		if ( ! $state_raw ) {
			return $this->error_redirect( 'Invalid or expired SSO state. Please try again.' );
		}

		$state_data = json_decode( $state_raw, true );
		$idp_id     = $state_data['idp_id'] ?? '';
		$idp        = IdpManager::find( $idp_id );

		if ( ! $idp ) {
			return $this->error_redirect( 'Identity Provider not found.' );
		}

		$claims = $this->extract_saml_claims( $idp, $saml_response_b64 );

		if ( is_wp_error( $claims ) ) {
			return $this->error_redirect( $claims->get_error_message() );
		}

		$result = $this->provision_and_login( $idp, $claims );

		if ( is_wp_error( $result ) ) {
			return $this->error_redirect( $result->get_error_message() );
		}

		return $this->success_redirect();
	}

	/**
	 * Parse and verify the SAML Response, extracting user claims.
	 *
	 * @return array|\WP_Error  Array with 'email', 'name', 'groups' keys.
	 */
	private function extract_saml_claims( array $idp, string $saml_response_b64 ) {
		try {
			$xml = base64_decode( $saml_response_b64, true );

			if ( $xml === false ) {
				return new \WP_Error( 'sso_error', 'Invalid SAML response encoding.' );
			}

			// Parse the XML using SimpleSAML library.
			$document = \SimpleSAML\XML\DOMDocumentFactory::fromString( $xml );
			$response = \SimpleSAML\SAML2\XML\samlp\Response::fromXML( $document->documentElement );

			$assertions = $response->getAssertions();
			if ( empty( $assertions ) ) {
				return new \WP_Error( 'sso_error', 'No assertions in SAML response.' );
			}

			$assertion = $assertions[0];

			// Verify signature if certificate is configured.
			$certificate = trim( $idp['certificate'] ?? '' );
			if ( $certificate ) {
				$key = \SimpleSAML\XMLSecurity\Key\PublicKey::fromCertificateData( $certificate );
				if ( ! $assertion->wasSignedAtConstruction() ) {
					return new \WP_Error( 'sso_error', 'SAML assertion is not signed.' );
				}
				$assertion->verify( $key );
			}

			// Extract claims from attributes.
			$attributes = [];
			foreach ( $assertion->getStatements() as $statement ) {
				if ( $statement instanceof \SimpleSAML\SAML2\XML\saml\AttributeStatement ) {
					foreach ( $statement->getAttributes() as $attr ) {
						$name   = $attr->getName();
						$values = [];
						foreach ( $attr->getAttributeValues() as $av ) {
							$values[] = $av->getString();
						}
						$attributes[ $name ] = $values;
					}
				}
			}

			// Try common attribute names for email.
			$email = $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'][0]
				?? $attributes['urn:oid:0.9.2342.19200300.100.1.3'][0]
				?? $attributes['email'][0]
				?? null;

			if ( ! $email ) {
				// Try NameID as fallback.
				$subject = $assertion->getSubject();
				if ( $subject ) {
					$name_id = $subject->getIdentifier();
					if ( $name_id instanceof \SimpleSAML\SAML2\XML\saml\NameID ) {
						$email = $name_id->getContent();
					}
				}
			}

			if ( ! $email || ! is_email( $email ) ) {
				return new \WP_Error( 'sso_error', 'Could not extract a valid email from the SAML assertion.' );
			}

			// Extract display name.
			$name = $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'][0]
				?? $attributes['urn:oid:2.16.840.1.113730.3.1.241'][0]
				?? $attributes['displayName'][0]
				?? '';

			// Extract groups.
			$groups = $attributes['http://schemas.xmlsoap.org/claims/Group'][0] ?? null;
			if ( is_string( $groups ) ) {
				$groups = [ $groups ];
			}
			$groups = $attributes['http://schemas.xmlsoap.org/claims/Group']
				?? $attributes['groups']
				?? $attributes['memberOf']
				?? [];

			return [
				'email'  => sanitize_email( $email ),
				'name'   => sanitize_text_field( $name ),
				'groups' => array_map( 'sanitize_text_field', (array) $groups ),
			];
		} catch ( \Throwable $e ) {
			return new \WP_Error( 'sso_error', 'SAML verification failed: ' . $e->getMessage() );
		}
	}

	// ── JIT Provisioning ────────────────────────────────────────────────────

	/**
	 * Find or create a WP user based on SSO claims, set their role, and log them in.
	 *
	 * @param array $idp    The IdP configuration.
	 * @param array $claims Array with 'email', 'name', 'groups'.
	 * @return true|\WP_Error
	 */
	private function provision_and_login( array $idp, array $claims ) {
		$email = $claims['email'];
		$user  = get_user_by( 'email', $email );

		if ( ! $user ) {
			// JIT provisioning: create new user.
			$username = $this->generate_username( $email );
			$password = wp_generate_password( 32, true, true );

			$name_parts = explode( ' ', $claims['name'], 2 );
			$first_name = $name_parts[0] ?? '';
			$last_name  = $name_parts[1] ?? '';

			$user_id = wp_insert_user( [
				'user_login'   => $username,
				'user_email'   => $email,
				'user_pass'    => $password,
				'first_name'   => sanitize_text_field( $first_name ),
				'last_name'    => sanitize_text_field( $last_name ),
				'display_name' => $claims['name'] ?: $username,
				'role'         => 'subscriber', // default, overridden below
			] );

			if ( is_wp_error( $user_id ) ) {
				return $user_id;
			}

			$user = get_user_by( 'id', $user_id );

			// Mark this user as SSO-provisioned.
			update_user_meta( $user_id, '_enterprise_auth_sso_provider', $idp['id'] ?? '' );
		}

		// Role mapping: map IdP groups to WP roles.
		$this->apply_role_mapping( $user, $idp, $claims['groups'] );

		// Log the user in.
		wp_set_auth_cookie( $user->ID, true );
		do_action( 'wp_login', $user->user_login, $user );

		return true;
	}

	/**
	 * Map IdP group claims to WordPress roles.
	 */
	private function apply_role_mapping( \WP_User $user, array $idp, array $groups ): void {
		$mapping = $idp['role_mapping'] ?? [];

		if ( empty( $mapping ) || empty( $groups ) ) {
			return;
		}

		foreach ( $groups as $group ) {
			$group_lower = strtolower( $group );
			foreach ( $mapping as $idp_group => $wp_role ) {
				if ( strtolower( $idp_group ) === $group_lower ) {
					$user->set_role( $wp_role );
					return; // Apply highest-priority match only.
				}
			}
		}
	}

	/**
	 * Derive a unique username from an email address.
	 */
	private function generate_username( string $email ): string {
		$base = sanitize_user( strtok( $email, '@' ), true );

		if ( ! username_exists( $base ) ) {
			return $base;
		}

		$i = 2;
		while ( username_exists( $base . $i ) ) {
			$i++;
		}

		return $base . $i;
	}

	// ── Helpers ─────────────────────────────────────────────────────────────

	/**
	 * Decode a base64url string.
	 */
	private function base64url_decode( string $input ): string {
		$remainder = strlen( $input ) % 4;
		if ( $remainder ) {
			$input .= str_repeat( '=', 4 - $remainder );
		}
		return base64_decode( strtr( $input, '-_', '+/' ) );
	}

	/**
	 * Redirect to wp-login.php with an error message.
	 */
	private function error_redirect( string $message ): \WP_REST_Response {
		$url = add_query_arg( [
			'ea_sso_error' => rawurlencode( $message ),
		], wp_login_url() );

		return new \WP_REST_Response( null, 302, [ 'Location' => $url ] );
	}

	/**
	 * Redirect to the admin dashboard on successful login.
	 */
	private function success_redirect(): \WP_REST_Response {
		return new \WP_REST_Response( null, 302, [ 'Location' => admin_url() ] );
	}
}
