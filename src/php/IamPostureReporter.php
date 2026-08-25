<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class IamPostureReporter {

	private UserIdentityInspector $inspector;

	public function __construct( ?UserIdentityInspector $inspector = null ) {
		$this->inspector = $inspector ?? new UserIdentityInspector();
	}

	/**
	 * @return array<string, mixed>
	 */
	public function site_posture( ?int $blog_id = null ): array {
		$blog_id = $blog_id && $blog_id > 0 ? $blog_id : get_current_blog_id();

		return $this->with_blog(
			$blog_id,
			function () use ( $blog_id ): array {
				$user_ids    = $this->site_user_ids( $blog_id );
				$inspections = $this->inspector->inspect_many( $user_ids, $blog_id );
				$settings    = SettingsController::read();
				$providers   = CurrentSiteIdpManager::all_for_blog( $blog_id );
				$summary     = $this->summarize_inspections( $inspections );
				$findings    = $this->findings( $summary, $settings, count( $providers ) );

				return array(
					'scope'     => 'site',
					'blog_id'   => $blog_id,
					'site_name' => get_bloginfo( 'name' ),
					'site_url'  => home_url( '/' ),
					'score'     => $this->score( $findings ),
					'findings'  => $findings,
					'summary'   => $summary,
					'settings'  => array(
						'lockdown_mode'                  => (bool) ( $settings['lockdown_mode'] ?? false ),
						'app_passwords'                  => (bool) ( $settings['app_passwords'] ?? false ),
						'require_device_bound_authenticators' => (bool) ( $settings['require_device_bound_authenticators'] ?? false ),
						'private_content_login_required' => (bool) ( $settings['private_content_login_required'] ?? false ),
						'role_ceiling'                   => (string) ( $settings['role_ceiling'] ?? '' ),
						'session_timeout'                => (int) ( $settings['session_timeout'] ?? 0 ),
					),
					'providers' => $this->provider_summary( $providers ),
				);
			}
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	public function network_posture(): array {
		if ( ! is_multisite() ) {
			return $this->site_posture();
		}

		$sites       = get_sites( array( 'number' => 0 ) );
		$site_rows   = array();
		$total_score = 0;

		foreach ( $sites as $site ) {
			$site_posture = $this->site_posture( (int) $site->blog_id );
			$assignment   = SiteAssignmentManager::read_for_blog( (int) $site->blog_id );
			$total_score += (int) $site_posture['score'];

			$site_rows[] = array(
				'blog_id'                 => (int) $site->blog_id,
				'name'                    => (string) ( $site_posture['site_name'] ?? '' ),
				'url'                     => (string) ( $site_posture['site_url'] ?? '' ),
				'score'                   => (int) $site_posture['score'],
				'user_count'              => (int) ( $site_posture['summary']['users']['total'] ?? 0 ),
				'local_users'             => (int) ( $site_posture['summary']['identity_sources']['local'] ?? 0 ),
				'legacy_passkeys'         => (int) ( $site_posture['summary']['passkeys']['legacy_non_compliant'] ?? 0 ),
				'users_requiring_step_up' => (int) ( $site_posture['summary']['passkeys']['users_requiring_step_up'] ?? 0 ),
				'assigned_provider_count' => count( $assignment['assigned_idp_ids'] ?? array() ),
				'finding_count'           => count( $site_posture['findings'] ?? array() ),
			);
		}

		$site_count = count( $site_rows );

		return array(
			'scope'   => 'network',
			'score'   => $site_count > 0 ? (int) round( $total_score / $site_count ) : 100,
			'sites'   => $site_rows,
			'summary' => array(
				'site_count'              => $site_count,
				'sites_needing_attention' => count( array_filter( $site_rows, static fn( array $site ): bool => (int) $site['score'] < 80 ) ),
				'unassigned_sites'        => count( array_filter( $site_rows, static fn( array $site ): bool => 0 === (int) $site['assigned_provider_count'] ) ),
				'total_users'             => array_sum( array_map( static fn( array $site ): int => (int) $site['user_count'], $site_rows ) ),
				'legacy_passkeys'         => array_sum( array_map( static fn( array $site ): int => (int) $site['legacy_passkeys'], $site_rows ) ),
				'users_requiring_step_up' => array_sum( array_map( static fn( array $site ): int => (int) $site['users_requiring_step_up'], $site_rows ) ),
			),
		);
	}

	/**
	 * @param array<int, array<string, mixed>> $inspections
	 * @return array<string, mixed>
	 */
	private function summarize_inspections( array $inspections ): array {
		$summary = array(
			'users'            => array(
				'total'     => count( $inspections ),
				'suspended' => 0,
			),
			'identity_sources' => array(
				'local' => 0,
				'sso'   => 0,
				'scim'  => 0,
				'mixed' => 0,
			),
			'passkeys'         => array(
				'total'                   => 0,
				'compliant'               => 0,
				'legacy_non_compliant'    => 0,
				'users_with_passkeys'     => 0,
				'users_without_passkeys'  => 0,
				'users_requiring_step_up' => 0,
				'latest_last_used_at'     => 0,
			),
		);

		foreach ( $inspections as $inspection ) {
			$source = (string) ( $inspection['identity_source'] ?? 'local' );
			if ( ! isset( $summary['identity_sources'][ $source ] ) ) {
				$source = 'local';
			}
			++$summary['identity_sources'][ $source ];

			if ( ! empty( $inspection['suspended_site'] ) || ! empty( $inspection['suspended_network'] ) ) {
				++$summary['users']['suspended'];
			}

			$passkeys                                     = is_array( $inspection['passkeys'] ?? null ) ? $inspection['passkeys'] : array();
			$total                                        = (int) ( $passkeys['total'] ?? 0 );
			$summary['passkeys']['total']                += $total;
			$summary['passkeys']['compliant']            += (int) ( $passkeys['compliant'] ?? 0 );
			$summary['passkeys']['legacy_non_compliant'] += (int) ( $passkeys['legacy_non_compliant'] ?? 0 );
			++$summary['passkeys'][ $total > 0 ? 'users_with_passkeys' : 'users_without_passkeys' ];

			if ( ! empty( $passkeys['step_up_required'] ) ) {
				++$summary['passkeys']['users_requiring_step_up'];
			}

			$summary['passkeys']['latest_last_used_at'] = max(
				(int) $summary['passkeys']['latest_last_used_at'],
				(int) ( $passkeys['last_used_at'] ?? 0 )
			);
		}

		return $summary;
	}

	/**
	 * @param array<string, mixed> $summary
	 * @param array<string, mixed> $settings
	 * @return array<int, array<string, mixed>>
	 */
	private function findings( array $summary, array $settings, int $provider_count ): array {
		$findings = array();

		if ( 0 === $provider_count ) {
			$findings[] = $this->finding( 'no_identity_provider', 'critical', 'No identity provider is configured for this site.', 20 );
		}

		if ( (int) $summary['identity_sources']['local'] > 0 ) {
			$findings[] = $this->finding( 'local_accounts_present', 'warning', 'Local accounts are present alongside enterprise identity controls.', 15 );
		}

		if ( (int) $summary['passkeys']['users_without_passkeys'] > 0 ) {
			$findings[] = $this->finding( 'users_without_passkeys', 'warning', 'Some users have no registered passkey.', 15 );
		}

		if ( (int) $summary['passkeys']['legacy_non_compliant'] > 0 ) {
			$findings[] = $this->finding( 'legacy_passkeys', 'critical', 'Legacy non-compliant passkeys require migration.', 15 );
		}

		if ( (int) $summary['passkeys']['users_requiring_step_up'] > 0 ) {
			$findings[] = $this->finding( 'step_up_required', 'warning', 'Some users still need passkey step-up.', 10 );
		}

		if ( ! empty( $settings['app_passwords'] ) ) {
			$findings[] = $this->finding( 'application_passwords_enabled', 'warning', 'Application passwords are enabled for non-admin users.', 10 );
		}

		if ( empty( $settings['private_content_login_required'] ) ) {
			$findings[] = $this->finding( 'private_content_gate_disabled', 'info', 'Private content login gate is disabled.', 5 );
		}

		return $findings;
	}

	/**
	 * @return array<string, mixed>
	 */
	private function finding( string $code, string $severity, string $message, int $weight ): array {
		return array(
			'code'     => $code,
			'severity' => $severity,
			'message'  => $message,
			'weight'   => $weight,
		);
	}

	/**
	 * @param array<int, array<string, mixed>> $providers
	 * @return array<string, mixed>
	 */
	private function provider_summary( array $providers ): array {
		$summary = array(
			'total' => count( $providers ),
			'saml'  => 0,
			'oidc'  => 0,
		);

		foreach ( $providers as $provider ) {
			$protocol = (string) ( $provider['protocol'] ?? '' );
			if ( isset( $summary[ $protocol ] ) ) {
				++$summary[ $protocol ];
			}
		}

		return $summary;
	}

	/**
	 * @param array<int, array<string, mixed>> $findings
	 */
	private function score( array $findings ): int {
		$penalty = array_sum( array_map( static fn( array $finding ): int => (int) ( $finding['weight'] ?? 0 ), $findings ) );

		return max( 0, 100 - $penalty );
	}

	/**
	 * @return array<int>
	 */
	private function site_user_ids( int $blog_id ): array {
		return array_map(
			'intval',
			get_users(
				array(
					'fields'  => 'ids',
					'blog_id' => $blog_id,
				)
			)
		);
	}

	private function with_blog( int $blog_id, callable $callback ): mixed {
		if ( ! is_multisite() || $blog_id <= 0 || get_current_blog_id() === $blog_id ) {
			return $callback();
		}

		switch_to_blog( $blog_id );
		try {
			return $callback();
		} finally {
			restore_current_blog();
		}
	}
}
