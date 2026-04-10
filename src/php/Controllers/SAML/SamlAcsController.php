<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\IdpManager;
use EnterpriseAuth\Plugin\EnterpriseProvisioning;
use EnterpriseAuth\Plugin\SamlSettingsFactory;

/**
 * SAML Assertion Consumer Service (ACS).
 *
 * Receives the SAML Response from the IdP, validates the signature,
 * extracts user attributes, and invokes JIT provisioning.
 *
 * Route: POST /enterprise-auth/v1/saml/acs
 */
final class SamlAcsController {

	private const NAMESPACE = 'enterprise-auth/v1';

	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/saml/acs',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'consume' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Process the incoming SAML Response.
	 */
	public function consume( \WP_REST_Request $request ): \WP_REST_Response {
		$saml_response = $request->get_param( 'SAMLResponse' );
		$relay_state   = $request->get_param( 'RelayState' );

		if ( empty( $saml_response ) ) {
			return $this->error_redirect( 'Missing SAMLResponse.' );
		}

		// RelayState carries the IdP ID set by SamlLoginController.
		$idp_id = sanitize_text_field( $relay_state ?? '' );
		$idp    = IdpManager::find( $idp_id );

		if ( ! $idp || ( $idp['protocol'] ?? '' ) !== 'saml' ) {
			return $this->error_redirect( 'SAML IdP configuration not found.' );
		}

		try {
			$settings = SamlSettingsFactory::build( $idp );
			$auth     = new \OneLogin\Saml2\Auth( $settings );

			// Inject the SAMLResponse into $_POST so the library can read it.
			// The OneLogin library reads directly from $_POST.
			$_POST['SAMLResponse'] = $saml_response;
			if ( $relay_state ) {
				$_POST['RelayState'] = $relay_state;
			}

			// Retrieve and consume the stored AuthnRequest ID for
			// InResponseTo validation (prevents unsolicited response replay).
			$transient_key = 'ea_saml_reqid_' . $idp_id;
			$request_id    = get_transient( $transient_key );
			delete_transient( $transient_key );

			$auth->processResponse( $request_id ?: null );

			$errors = $auth->getErrors();
			if ( ! empty( $errors ) ) {
				$reason = $auth->getLastErrorReason();
				return $this->error_redirect(
					'SAML validation failed: ' . implode( ', ', $errors )
					. ( $reason ? ' — ' . $reason : '' )
				);
			}

			if ( ! $auth->isAuthenticated() ) {
				return $this->error_redirect( 'SAML authentication was not successful.' );
			}

			// Extract user attributes.
			$attributes = $this->extract_attributes( $auth, $idp );

			// Honour SAML SessionNotOnOrAfter if the IdP provided one.
			$session_expiry = $auth->getSessionExpiration();
			if ( ! empty( $session_expiry ) ) {
				$attributes['session_not_on_or_after'] = (int) $session_expiry;
			}

			// Store the SAML IdP entity ID as the canonical issuer identifier.
			$attributes['idp_issuer'] = sanitize_text_field( $idp['entity_id'] ?? '' );

			// JIT provisioning and login.
			$result = EnterpriseProvisioning::provision_and_login( $idp, $attributes );

			if ( is_wp_error( $result ) ) {
				return $this->error_redirect( $result->get_error_message() );
			}

			return $this->success_redirect();
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Enterprise IAM – SAML ACS error: ' . $e->getMessage() );
			}
			return $this->error_redirect( 'SAML authentication failed. Please try again or contact your administrator.' );
		}
	}

	/**
	 * Extract user attributes from a validated SAML assertion.
	 *
	 * When the IdP has override_attribute_mapping enabled, the custom keys
	 * are used to read email, first name, and last name from the assertion.
	 *
	 * @param \OneLogin\Saml2\Auth $auth
	 * @param array<string, mixed> $idp  IdP configuration from IdpManager.
	 * @return array{email: string, first_name: string, last_name: string, groups: string[]}
	 */
	private function extract_attributes( \OneLogin\Saml2\Auth $auth, array $idp ): array {
		$attrs = $auth->getAttributes();

		$use_custom = ! empty( $idp['override_attribute_mapping'] );

		// ── Email ────────────────────────────────────────────────────────
		// NameID is the primary email source.
		$email = $auth->getNameId();

		if ( $use_custom && ! empty( $idp['custom_email_attr'] ) ) {
			$custom_email = $attrs[ $idp['custom_email_attr'] ][0] ?? '';
			if ( '' !== $custom_email ) {
				$email = $custom_email;
			}
		} elseif ( ! is_email( $email ) ) {
			// Fallback: try common attribute OIDs / claim URIs.
			$email = $attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'][0]
				?? $attrs['urn:oid:0.9.2342.19200300.100.1.3'][0]  // mail
				?? $attrs['email'][0]
				?? '';
		}

		// ── First name ──────────────────────────────────────────────────
		if ( $use_custom && ! empty( $idp['custom_first_name_attr'] ) ) {
			$first_name = $attrs[ $idp['custom_first_name_attr'] ][0] ?? '';
		} else {
			$first_name = $attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'][0]
				?? $attrs['urn:oid:2.5.4.42'][0]   // givenName
				?? $attrs['givenName'][0]
				?? $attrs['firstName'][0]
				?? '';
		}

		// ── Last name ───────────────────────────────────────────────────
		if ( $use_custom && ! empty( $idp['custom_last_name_attr'] ) ) {
			$last_name = $attrs[ $idp['custom_last_name_attr'] ][0] ?? '';
		} else {
			$last_name = $attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'][0]
				?? $attrs['urn:oid:2.5.4.4'][0]    // sn
				?? $attrs['sn'][0]
				?? $attrs['lastName'][0]
				?? '';
		}

		$groups = $attrs['http://schemas.xmlsoap.org/claims/Group']
			?? $attrs['groups']
			?? $attrs['memberOf']
			?? array();

		// Prefer a dedicated persistent-identifier attribute if configured,
		// since SAML NameID is often an email address and therefore mutable.
		$uid = '';
		if ( $use_custom && ! empty( $idp['custom_uid_attr'] ) ) {
			$uid = $attrs[ $idp['custom_uid_attr'] ][0] ?? '';
		}
		if ( '' === $uid ) {
			// Fallback: try well-known persistent-ID attributes.
			$uid = $attrs['http://schemas.microsoft.com/identity/claims/objectidentifier'][0]
				?? $attrs['urn:oid:0.9.2342.19200300.100.1.1'][0]  // uid
				?? '';
		}
		if ( '' === $uid ) {
			// Last resort: NameID.
			$name_id = $auth->getNameId();
			$uid     = is_string( $name_id ) ? $name_id : '';
		}

		return array(
			'email'          => $email,
			'first_name'     => $first_name,
			'last_name'      => $last_name,
			'groups'         => (array) $groups,
			'idp_uid'        => $uid,
			// SAML assertions are signed by the IdP; the signature verification
			// performed above inherently vouches for all attribute values
			// including email. Treat as email_verified unless overridden.
			'email_verified' => true,
		);
	}

	/**
	 * Redirect to wp-login.php with an error message.
	 */
	private function error_redirect( string $message ): \WP_REST_Response {
		$url = add_query_arg(
			array(
				'ea_sso_error' => rawurlencode( $message ),
			),
			wp_login_url()
		);

		return new \WP_REST_Response( null, 302, array( 'Location' => $url ) );
	}

	/**
	 * Redirect to wp-admin on successful login.
	 */
	private function success_redirect(): \WP_REST_Response {
		return new \WP_REST_Response( null, 302, array( 'Location' => admin_url() ) );
	}
}
