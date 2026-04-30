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
	private const NETWORK_MENU_SLUG = 'enterprise-auth-network';
	private const NETWORK_PROVIDERS_SLUG = 'enterprise-auth-network-providers';
	private const NETWORK_ASSIGNMENTS_SLUG = 'enterprise-auth-network-assignments';
	private const NETWORK_POLICY_SLUG = 'enterprise-auth-network-policy';
	private const STEP_UP_MENU_SLUG = 'enterprise-auth-security-upgrade';

	public function init(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'network_admin_menu', array( $this, 'register_network_menu' ) );
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

	public function register_network_menu(): void {
		if ( ! NetworkMode::is_network_mode() ) {
			return;
		}

		add_menu_page(
			__( 'Enterprise Auth', 'enterprise-auth' ),
			__( 'Enterprise Auth', 'enterprise-auth' ),
			'manage_network_options',
			self::NETWORK_MENU_SLUG,
			array( $this, 'render_network_overview_page' ),
			'dashicons-shield-alt',
			3
		);

		add_submenu_page(
			self::NETWORK_MENU_SLUG,
			__( 'Overview', 'enterprise-auth' ),
			__( 'Overview', 'enterprise-auth' ),
			'manage_network_options',
			self::NETWORK_MENU_SLUG,
			array( $this, 'render_network_overview_page' )
		);

		add_submenu_page(
			self::NETWORK_MENU_SLUG,
			__( 'Identity Providers', 'enterprise-auth' ),
			__( 'Identity Providers', 'enterprise-auth' ),
			'manage_network_options',
			self::NETWORK_PROVIDERS_SLUG,
			array( $this, 'render_network_providers_page' )
		);

		add_submenu_page(
			self::NETWORK_MENU_SLUG,
			__( 'Site Assignments', 'enterprise-auth' ),
			__( 'Site Assignments', 'enterprise-auth' ),
			'manage_network_options',
			self::NETWORK_ASSIGNMENTS_SLUG,
			array( $this, 'render_network_assignments_page' )
		);

		add_submenu_page(
			self::NETWORK_MENU_SLUG,
			__( 'Defaults & Policy', 'enterprise-auth' ),
			__( 'Defaults & Policy', 'enterprise-auth' ),
			'manage_network_options',
			self::NETWORK_POLICY_SLUG,
			array( $this, 'render_network_policy_page' )
		);
	}

	/**
	 * Render the mount-point div and enqueue React assets.
	 */
	public function render_page(): void {
		$this->enqueue_assets(
			array(
				'screen' => NetworkMode::is_network_mode() ? 'site-settings' : 'settings',
			)
		);

		echo '<div id="enterprise-auth-root"></div>';
	}

	public function render_network_overview_page(): void {
		$this->enqueue_assets( array( 'screen' => 'network-overview' ) );

		echo '<div id="enterprise-auth-root"></div>';
	}

	public function render_network_providers_page(): void {
		$this->enqueue_assets( array( 'screen' => 'network-idps' ) );

		echo '<div id="enterprise-auth-root"></div>';
	}

	public function render_network_assignments_page(): void {
		$this->enqueue_assets( array( 'screen' => 'network-assignments' ) );

		echo '<div id="enterprise-auth-root"></div>';
	}

	public function render_network_policy_page(): void {
		$this->enqueue_assets( array( 'screen' => 'network-policy' ) );

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
					'restUrl'             => esc_url_raw( rest_url( 'enterprise-auth/v1/' ) ),
					'nonce'               => wp_create_nonce( 'wp_rest' ),
					'screen'              => 'settings',
					'isNetworkMode'       => NetworkMode::is_network_mode(),
					'isNetworkAdmin'      => is_network_admin(),
					'isNetworkManagedSite' => ! is_network_admin() && CurrentSiteIdpManager::uses_network_control_plane(),
					'idpManagementScope'  => CurrentSiteIdpManager::uses_network_control_plane() ? 'network' : 'site',
					'blogId'              => get_current_blog_id(),
					'guideLinks'          => array(
						array(
							'label' => __( 'Entra ID SAML Guide', 'enterprise-auth' ),
							'url'   => esc_url_raw( ENTERPRISE_AUTH_URL . 'docs/customer-guides/Entra-ID-SAML-Setup.md' ),
						),
						array(
							'label' => __( 'Okta OIDC & SCIM Guide', 'enterprise-auth' ),
							'url'   => esc_url_raw( ENTERPRISE_AUTH_URL . 'docs/customer-guides/Okta-OIDC-SCIM-Setup.md' ),
						),
						array(
							'label' => __( 'SSO Troubleshooting', 'enterprise-auth' ),
							'url'   => esc_url_raw( ENTERPRISE_AUTH_URL . 'docs/customer-guides/Troubleshooting-SSO.md' ),
						),
					),
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
