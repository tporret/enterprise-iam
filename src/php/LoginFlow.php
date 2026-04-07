<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Injects the step-based login flow on wp-login.php.
 *
 * Step 1: "Enter your Email" – domain routing decides SSO or local.
 * Step 2 (local): Password form revealed + Passkey prompt.
 * Step 2 (SSO):  Redirect to the external IdP.
 */
final class LoginFlow {

	public function init(): void {
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_assets' ) );
		add_action( 'login_form', array( $this, 'render_step_ui' ) );
		add_action( 'login_message', array( $this, 'render_sso_error' ) );
		add_action( 'login_head', array( $this, 'render_identity_first_css' ) );
	}

	/**
	 * Enqueue the vanilla JS passkey-login script on wp-login.php.
	 */
	public function enqueue_login_assets(): void {
		$version = ENTERPRISE_AUTH_VERSION;

		wp_enqueue_style(
			'enterprise-auth-passkey-login',
			ENTERPRISE_AUTH_URL . 'build/passkey-login.css',
			array(),
			$version
		);

		wp_enqueue_script(
			'enterprise-auth-passkey-login',
			ENTERPRISE_AUTH_URL . 'build/passkey-login.js',
			array(),
			$version,
			true
		);

		wp_localize_script(
			'enterprise-auth-passkey-login',
			'eaPasskeyLogin',
			array(
				'restUrl' => esc_url_raw( rest_url( 'enterprise-auth/v1/' ) ),
				'nonce'   => wp_create_nonce( 'wp_rest' ),
			)
		);
	}

	/**
	 * Hide password / submit fields until the email routing resolves.
	 *
	 * Printed in <head> so there is no flash of unstyled content.
	 */
	public function render_identity_first_css(): void {
		?>
		<style>
			/* Hide step-2 fields until JS reveals them */
			.login-password,
			.user-pass-wrap,
			#loginform > .forgetmenot,
			#loginform > p.submit { display: none; }

			#loginform label[for="user_login"] { /* rewritten by JS */ }
		</style>
		<?php
	}

	/**
	 * Render the step-based login UI inside the WP login form.
	 */
	public function render_step_ui(): void {
		?>
		<!-- Step 1: Continue button (email is the WP user_login field above) -->
		<div id="ea-step-continue" class="ea-login-step">
			<button
				type="button"
				id="ea-route-btn"
				class="button button-primary button-large"
			>
				<?php echo esc_html__( 'Continue', 'enterprise-auth' ); ?>
			</button>
			<p id="ea-route-status" class="ea-login-status"></p>
		</div>

		<!-- Step 2: Passkey alternative (hidden until routing resolves to local) -->
		<div id="ea-step-passkey" class="ea-login-step" style="display: none;">
			<div class="ea-login-divider">
				<span><?php echo esc_html__( 'or', 'enterprise-auth' ); ?></span>
			</div>
			<button
				type="button"
				id="ea-passkey-login-btn"
				class="button button-secondary button-large ea-passkey-btn"
			>
				<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
					stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
					<path d="M7 11V7a5 5 0 0 1 10 0v4"/>
				</svg>
				<?php echo esc_html__( 'Log in with Passkey', 'enterprise-auth' ); ?>
			</button>
			<p id="ea-passkey-status" class="ea-login-status"></p>
		</div>

		<!-- Back link (hidden until step 2) -->
		<p id="ea-back-link" class="ea-login-step" style="display: none;">
			<a href="#" id="ea-back-btn">&larr; <?php echo esc_html__( 'Use a different account', 'enterprise-auth' ); ?></a>
		</p>
		<?php
	}

	/**
	 * Display SSO error messages returned via query string.
	 */
	public function render_sso_error( string $message ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET['ea_sso_error'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$error    = sanitize_text_field( wp_unslash( $_GET['ea_sso_error'] ) );
			$message .= '<div id="login_error"><strong>SSO Error:</strong> ' . esc_html( $error ) . '</div>';
		}
		return $message;
	}
}
