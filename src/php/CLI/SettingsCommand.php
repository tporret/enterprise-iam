<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\CLI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SettingsCommand extends BaseCommand {

	public function get( array $_args, array $assoc_args ): void {
		$format = $this->get_format( $assoc_args, array( 'table', 'json' ) );
		$this->render_assoc( $this->read_settings_payload( $assoc_args ), $format );
	}
}