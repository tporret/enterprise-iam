<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\CLI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class UserCommand extends BaseCommand {

	public function inspect( array $args, array $assoc_args ): void {
		$user   = $this->resolve_user( (string) ( $args[0] ?? '' ) );
		$scope  = $this->resolve_scope_args( $assoc_args, false, is_multisite() );
		$format = $this->get_format( $assoc_args, array( 'table', 'json' ) );
		$data   = $this->identity_inspector->inspect( $user, $scope['blog_id'] );

		$this->render_assoc(
			array_merge(
				array(
					'user_id' => $user->ID,
					'user_login' => $user->user_login,
					'user_email' => $user->user_email,
					'blog_id' => (int) ( $data['blog_id'] ?? ( $scope['blog_id'] ?? get_current_blog_id() ) ),
					'identity_source' => $this->identity_label( (string) ( $data['identity_source'] ?? 'local' ) ),
				),
				$data,
				array(
					'last_sso_login_at' => $this->format_timestamp( (int) ( $data['last_sso_login_at'] ?? 0 ) ),
					'session_expires_at' => $this->format_timestamp( (int) ( $data['session_expires_at'] ?? 0 ) ),
				)
			),
			$format
		);
	}

	public function site_status( array $args, array $assoc_args ): void {
		if ( empty( $assoc_args['blog-id'] ) && empty( $assoc_args['blog_id'] ) ) {
			\WP_CLI::error( 'user site-status requires --blog-id=<id>.' );
		}

		$this->inspect( $args, $assoc_args );
	}

	public function passkeys( array $args, array $assoc_args ): void {
		$user   = $this->resolve_user( (string) ( $args[0] ?? '' ) );
		$scope  = $this->resolve_scope_args( $assoc_args, false, is_multisite() );
		$format = $this->get_format( $assoc_args, array( 'table', 'json' ) );
		$data   = $this->with_blog(
			$scope['blog_id'],
			function () use ( $user ): array {
				$summary = \EnterpriseAuth\Plugin\CredentialRepository::passkey_summaries_for_users( array( $user->ID ) );
				$identity = $this->identity_inspector->inspect( $user );

				return array(
					'user_id' => $user->ID,
					'user_login' => $user->user_login,
					'blog_id' => get_current_blog_id(),
					'total' => (int) ( $summary[ $user->ID ]['total'] ?? 0 ),
					'compliant' => (int) ( $summary[ $user->ID ]['compliant'] ?? 0 ),
					'legacy_non_compliant' => (int) ( $summary[ $user->ID ]['legacy_non_compliant'] ?? 0 ),
					'last_used_at' => $this->format_timestamp( strtotime( (string) ( $summary[ $user->ID ]['last_used_at'] ?? '' ) . ' UTC' ) ?: 0 ),
					'step_up_required' => (bool) ( $identity['passkeys']['step_up_required'] ?? false ),
				);
			}
		);

		$this->render_assoc( $data, $format );
	}
}