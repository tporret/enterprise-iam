<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\CLI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Bootstrap {

	public static function register(): void {
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}

		\WP_CLI::add_command( 'enterprise-auth provider', ProviderCommand::class );
		\WP_CLI::add_command( 'enterprise-auth site', SiteCommand::class );
		\WP_CLI::add_command( 'enterprise-auth user', UserCommand::class );
		\WP_CLI::add_command( 'enterprise-auth settings', SettingsCommand::class );
		\WP_CLI::add_command( 'enterprise-auth route', RouteCommand::class );
		\WP_CLI::add_command( 'enterprise-auth passkey', PasskeyCommand::class );
		\WP_CLI::add_command( 'enterprise-auth scim', ScimCommand::class );
	}
}