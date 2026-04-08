<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use EnterpriseAuth\Plugin\Controllers\IdpController;
use EnterpriseAuth\Plugin\Controllers\LoginRouter;
use EnterpriseAuth\Plugin\Controllers\OIDC\OidcCallbackController;
use EnterpriseAuth\Plugin\Controllers\OIDC\OidcLoginController;
use EnterpriseAuth\Plugin\Controllers\PasskeyLoginController;
use EnterpriseAuth\Plugin\Controllers\PasskeyRegistrationController;
use EnterpriseAuth\Plugin\Controllers\SAML\SamlAcsController;
use EnterpriseAuth\Plugin\Controllers\SAML\SamlLoginController;
use EnterpriseAuth\Plugin\Controllers\SAML\SamlMetadataController;

/**
 * Core bootstrap class.
 *
 * Wires all plugin sub-systems together.
 */
final class Core {

	public function init(): void {
		// Security hardening – runs on every request.
		( new SecurityManager() )->init();

		// Admin UI – only in wp-admin context.
		if ( is_admin() ) {
			( new AdminUI() )->init();
		}

		// REST API controllers.
		add_action(
			'rest_api_init',
			static function (): void {
				( new SettingsController() )->register_routes();
				( new PasskeyRegistrationController() )->register_routes();
				( new PasskeyLoginController() )->register_routes();
				( new IdpController() )->register_routes();
				( new LoginRouter() )->register_routes();
				( new SamlMetadataController() )->register_routes();
				( new SamlLoginController() )->register_routes();
				( new SamlAcsController() )->register_routes();
				( new OidcLoginController() )->register_routes();
				( new OidcCallbackController() )->register_routes();
			}
		);

		// Passkey login injection on wp-login.php.
		( new LoginFlow() )->init();

		// Security headers on frontend.
		add_action( 'send_headers', array( $this, 'send_security_headers' ) );
	}

	/**
	 * Append strict security headers when they are not already present.
	 */
	public function send_security_headers(): void {
		$headers = array(
			'X-Frame-Options'        => 'SAMEORIGIN',
			'X-Content-Type-Options' => 'nosniff',
			'Referrer-Policy'        => 'strict-origin-when-cross-origin',
			'Permissions-Policy'     => 'geolocation=(), camera=(), microphone=()',
		);

		foreach ( $headers as $name => $value ) {
			if ( ! headers_sent() ) {
				header( sprintf( '%s: %s', $name, $value ), false );
			}
		}
	}
}
