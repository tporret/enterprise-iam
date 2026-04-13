<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\CLI;

use EnterpriseAuth\Plugin\LoginRouteResolver;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RouteCommand extends BaseCommand {

	public function resolve( array $args, array $assoc_args ): void {
		$scope    = $this->resolve_scope_args( $assoc_args, false, is_multisite() );
		$format   = $this->get_format( $assoc_args, array( 'table', 'json' ) );
		$resolver = new LoginRouteResolver();
		$result   = $resolver->resolve( (string) ( $args[0] ?? '' ), $scope['blog_id'] );

		$this->render_assoc( $result, $format );
	}
}