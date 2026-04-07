<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Admin UI — registers the top-level menu and enqueues the React SPA.
 */
final class AdminUI {

	private const MENU_SLUG = 'enterprise-auth';

	public function init(): void {
		add_action( 'admin_menu', [ $this, 'register_menu' ] );
	}

	/**
	 * Register the top-level "Enterprise Auth" admin menu page.
	 */
	public function register_menu(): void {
		add_menu_page(
			__( 'Enterprise Auth', 'enterprise-auth' ),
			__( 'Enterprise Auth', 'enterprise-auth' ),
			'manage_options',
			self::MENU_SLUG,
			[ $this, 'render_page' ],
			'dashicons-shield-alt',
			3
		);
	}

	/**
	 * Render the mount-point div and enqueue React assets.
	 */
	public function render_page(): void {
		$this->enqueue_assets();

		echo '<div id="enterprise-auth-root"></div>';
	}

	/**
	 * Enqueue the compiled React app and pass localised data.
	 */
	private function enqueue_assets(): void {
		$asset_file = ENTERPRISE_AUTH_DIR . 'build/index.asset.php';

		if ( ! file_exists( $asset_file ) ) {
			return;
		}

		$asset = require $asset_file;

		wp_enqueue_script(
			'enterprise-auth-admin',
			ENTERPRISE_AUTH_URL . 'build/index.js',
			$asset['dependencies'],
			$asset['version'],
			true
		);

		wp_enqueue_style(
			'enterprise-auth-admin',
			ENTERPRISE_AUTH_URL . 'build/style-index.css',
			[],
			$asset['version']
		);

		wp_localize_script( 'enterprise-auth-admin', 'enterpriseAuth', [
			'restUrl' => esc_url_raw( rest_url( 'enterprise-auth/v1/' ) ),
			'nonce'   => wp_create_nonce( 'wp_rest' ),
		] );
	}
}
