<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\Controllers\SAML;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\FederationErrorHandler;
use EnterpriseAuth\Plugin\FederationFlowGuard;
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
	private const PUBLIC_ERROR_CODE = 'federation_failed';
	private string $last_error_reference = '';

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
		$log_context   = array(
			'phase' => 'acs_entry',
		);

		if ( empty( $saml_response ) ) {
			$this->log_detailed_error( 'Missing SAMLResponse.', array( 'phase' => 'parameter_validation' ) );
			return $this->error_redirect();
		}

		$flow_key  = sanitize_text_field( (string) ( $relay_state ?? '' ) );
		$flow_data = FederationFlowGuard::consume( 'saml', $flow_key );
		if ( is_wp_error( $flow_data ) ) {
			$this->log_detailed_error(
				$flow_data->get_error_message(),
				$log_context + array( 'phase' => 'flow_validation' )
			);
			return $this->error_redirect();
		}

		$idp_id     = sanitize_text_field( (string) ( $flow_data['idp_id'] ?? '' ) );
		$request_id = sanitize_text_field( (string) ( $flow_data['request_id'] ?? '' ) );
		$idp        = IdpManager::find( $idp_id );
		$log_context['idp_id']   = $idp_id;
		$log_context['flow_key'] = $flow_key;

		if ( ! $idp || ( $idp['protocol'] ?? '' ) !== 'saml' || '' === $request_id ) {
			$this->log_detailed_error(
				'SAML ACS could not resolve a valid IdP configuration or request binding.',
				$log_context + array( 'phase' => 'idp_resolution' )
			);
			return $this->error_redirect();
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

			$auth->processResponse( $request_id );

			$errors = $auth->getErrors();
			if ( ! empty( $errors ) ) {
				$reason = $auth->getLastErrorReason();
				$this->log_detailed_error(
					'SAML validation failed: ' . implode( ', ', $errors )
					. ( $reason ? ' — ' . $reason : '' ),
					$log_context + array( 'phase' => 'assertion_validation' )
				);
				return $this->error_redirect();
			}

			if ( ! $auth->isAuthenticated() ) {
				$this->log_detailed_error(
					'SAML authentication was not successful.',
					$log_context + array( 'phase' => 'authentication' )
				);
				return $this->error_redirect();
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
				$this->log_detailed_error(
					$result->get_error_message(),
					$log_context + array( 'phase' => 'provisioning' )
				);
				return $this->error_redirect();
			}

			return $this->success_redirect();
		} catch ( \Throwable $e ) {
			$this->log_detailed_error(
				'Unhandled exception during SAML ACS processing.',
				$log_context + array( 'phase' => 'acs_exception' ),
				$e
			);
			return $this->error_redirect();
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
	 * Redirect to wp-login.php with a generic SSO error code.
	 */
	private function error_redirect(): \WP_REST_Response {
		$url = FederationErrorHandler::login_error_url( self::PUBLIC_ERROR_CODE, $this->last_error_reference );

		return new \WP_REST_Response( null, 302, array( 'Location' => $url ) );
	}

	/**
	 * Log the detailed protocol error for administrator troubleshooting.
	 */
	private function log_detailed_error( string $detail, array $context = array(), ?\Throwable $exception = null ): void {
		$this->last_error_reference = FederationErrorHandler::log(
			'saml',
			'saml_acs',
			$detail,
			$context,
			$exception
		);
	}

	/**
	 * Redirect to wp-admin on successful login.
	 */
	private function success_redirect(): \WP_REST_Response {
		return new \WP_REST_Response( null, 302, array( 'Location' => admin_url() ) );
	}

}
