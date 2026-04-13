<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\CLI;

use EnterpriseAuth\Plugin\CurrentSiteIdpManager;
use EnterpriseAuth\Plugin\SettingsController;
use EnterpriseAuth\Plugin\SiteAssignmentManager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SiteCommand extends BaseCommand {

	/**
	 * List sites and their IAM assignment state.
	 *
	 * @subcommand list
	 */
	public function list_( array $_args, array $assoc_args ): void {
		$format = $this->get_format( $assoc_args );
		$rows   = array();

		if ( ! is_multisite() ) {
			$assignment = SiteAssignmentManager::read_for_current_site();
			$rows[]     = array(
				'blog_id' => get_current_blog_id(),
				'url' => home_url( '/' ),
				'name' => get_bloginfo( 'name' ),
				'assigned_provider_count' => count( $assignment['assigned_idp_ids'] ),
				'primary_provider_id' => $assignment['primary_idp_id'],
			);
		} else {
			foreach ( get_sites( array( 'number' => 0 ) ) as $site ) {
				$blog_id    = (int) $site->blog_id;
				$assignment = SiteAssignmentManager::read_for_blog( $blog_id );
				$details    = get_blog_details( $blog_id );

				$rows[] = array(
					'blog_id' => $blog_id,
					'url' => (string) ( $details->siteurl ?? $site->siteurl ?? '' ),
					'name' => (string) ( $details->blogname ?? '' ),
					'assigned_provider_count' => count( $assignment['assigned_idp_ids'] ),
					'primary_provider_id' => $assignment['primary_idp_id'],
				);
			}
		}

		$this->render_rows( $rows, array( 'blog_id', 'url', 'name', 'assigned_provider_count', 'primary_provider_id' ), $format );
	}

	public function assignments( array $args, array $assoc_args ): void {
		$blog_id = (int) ( $args[0] ?? 0 );
		$format  = $this->get_format( $assoc_args, array( 'table', 'json' ) );
		$this->render_assoc( SiteAssignmentManager::read_for_blog( $blog_id ), $format );
	}

	public function policy( array $args, array $assoc_args ): void {
		$blog_id = (int) ( $args[0] ?? 0 );
		$format  = $this->get_format( $assoc_args, array( 'table', 'json' ) );

		$payload = $this->with_blog(
			$blog_id,
			static fn(): array => SettingsController::read()
		);

		$this->render_assoc( $payload, $format );
	}

	public function audit( array $args, array $assoc_args ): void {
		$blog_id     = (int) ( $args[0] ?? 0 );
		$format      = $this->get_format( $assoc_args, array( 'table', 'json' ) );
		$assignment  = SiteAssignmentManager::read_for_blog( $blog_id );
		$settings    = $this->with_blog( $blog_id, static fn(): array => SettingsController::read() );
		$user_ids    = $this->site_user_ids( $blog_id );
		$passkeys    = $this->aggregate_passkey_summaries( $user_ids, $blog_id );
		$inspections = $this->identity_inspector->inspect_many( $user_ids, $blog_id );
		$step_up     = 0;

		foreach ( $inspections as $inspection ) {
			if ( ! empty( $inspection['passkeys']['step_up_required'] ) ) {
				++$step_up;
			}
		}

		$this->render_assoc(
			array(
				'blog_id' => $blog_id,
				'assigned_provider_ids' => $assignment['assigned_idp_ids'],
				'primary_provider_id' => $assignment['primary_idp_id'],
				'effective_settings' => $settings,
				'passkey_strict_mode' => (bool) ( $settings['require_device_bound_authenticators'] ?? false ),
				'override_allowances' => $settings['scope_meta'] ?? array(),
				'legacy_non_compliant_passkeys' => (int) $passkeys['legacy_non_compliant'],
				'compliant_passkeys' => (int) $passkeys['compliant'],
				'users_with_step_up_required' => $step_up,
				'user_count' => count( $user_ids ),
			),
			$format
		);
	}
}