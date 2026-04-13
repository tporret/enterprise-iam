<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\CLI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ScimCommand extends BaseCommand {

	public function status( array $_args, array $assoc_args ): void {
		$scope  = $this->resolve_scope_args( $assoc_args, false, is_multisite() );
		$format = $this->get_format( $assoc_args, array( 'table', 'json' ) );

		$data = $this->with_blog(
			$scope['blog_id'],
			static function (): array {
				$settings = \EnterpriseAuth\Plugin\SettingsController::read();
				$hash     = (string) get_option( 'enterprise_iam_scim_token', '' );

				return array(
					'blog_id' => get_current_blog_id(),
					'base_url' => rest_url( 'enterprise-auth/v1/scim/v2/' ),
					'token_configured' => '' !== $hash,
					'deprovision_steward_user_id' => (int) ( $settings['deprovision_steward_user_id'] ?? 0 ),
					'deprovision_steward_options_count' => count( (array) ( $settings['deprovision_steward_options'] ?? array() ) ),
				);
			}
		);

		$this->render_assoc( $data, $format );
	}
}