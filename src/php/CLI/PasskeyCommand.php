<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\CLI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PasskeyCommand extends BaseCommand {

	public function audit( array $_args, array $assoc_args ): void {
		$scope    = $this->resolve_scope_args( $assoc_args, false, is_multisite() );
		$format   = $this->get_format( $assoc_args, array( 'table', 'json' ) );
		$user_ids = $this->site_user_ids( $scope['blog_id'] );
		$summary  = $this->aggregate_passkey_summaries( $user_ids, $scope['blog_id'] );
		$inspect  = $this->identity_inspector->inspect_many( $user_ids, $scope['blog_id'] );
		$step_up  = 0;

		foreach ( $inspect as $identity ) {
			if ( ! empty( $identity['passkeys']['step_up_required'] ) ) {
				++$step_up;
			}
		}

		$this->render_assoc(
			array(
				'blog_id' => (int) ( $scope['blog_id'] ?? get_current_blog_id() ),
				'user_count' => count( $user_ids ),
				'total_credentials' => (int) $summary['total'],
				'compliant_credentials' => (int) $summary['compliant'],
				'legacy_non_compliant_credentials' => (int) $summary['legacy_non_compliant'],
				'latest_last_used_at' => $this->format_timestamp( (int) $summary['latest_last_used_at'] ),
				'users_with_step_up_required' => $step_up,
			),
			$format
		);
	}
}