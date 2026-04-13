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
	private const STEP_UP_MENU_SLUG = 'enterprise-auth-security-upgrade';

	public function init(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
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
			array( $this, 'render_page' ),
			'dashicons-shield-alt',
			3
		);

		add_submenu_page(
			null,
			__( 'Security Upgrade Required', 'enterprise-auth' ),
			__( 'Security Upgrade Required', 'enterprise-auth' ),
			'read',
			self::STEP_UP_MENU_SLUG,
			array( $this, 'render_step_up_page' )
		);
	}

	/**
	 * Render the mount-point div and enqueue React assets.
	 */
	public function render_page(): void {
		$this->enqueue_assets( array( 'screen' => 'settings' ) );

		echo '<div id="enterprise-auth-root"></div>';
	}

	public function render_step_up_page(): void {
		if ( ! PasskeyPolicy::is_step_up_required_for_user( get_current_user_id() ) ) {
			wp_safe_redirect( admin_url() );
			exit;
		}

		$this->enqueue_assets(
			array(
				'screen' => 'stepup',
				'stepUpUrl' => self::step_up_url(),
				'logoutUrl' => wp_logout_url( wp_login_url() ),
			)
		);

		echo '<div id="enterprise-auth-root"></div>';
	}

	/**
	 * Enqueue the compiled React app and pass localised data.
	 */
	private function enqueue_assets( array $context = array() ): void {
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
			array(),
			$asset['version']
		);

		wp_localize_script(
			'enterprise-auth-admin',
			'enterpriseAuth',
			array_merge(
				array(
				'restUrl' => esc_url_raw( rest_url( 'enterprise-auth/v1/' ) ),
				'nonce'   => wp_create_nonce( 'wp_rest' ),
				'screen'  => 'settings',
			),
				$context
			)
		);
	}

	public static function step_up_page_slug(): string {
		return self::STEP_UP_MENU_SLUG;
	}

	public static function step_up_url(): string {
		return admin_url( 'admin.php?page=' . self::STEP_UP_MENU_SLUG );
	}
}
