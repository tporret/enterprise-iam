<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\CLI;

use EnterpriseAuth\Plugin\SettingsController;
use EnterpriseAuth\Plugin\UserIdentityInspector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class BaseCommand {

	protected const FORMATS = array( 'table', 'json', 'csv' );

	protected UserIdentityInspector $identity_inspector;

	public function __construct() {
		$this->identity_inspector = new UserIdentityInspector();
	}

	/**
	 * @param array<string, mixed> $assoc_args
	 */
	protected function get_format( array $assoc_args, array $allowed = self::FORMATS ): string {
		$format = isset( $assoc_args['format'] ) ? strtolower( (string) $assoc_args['format'] ) : 'table';

		if ( ! in_array( $format, $allowed, true ) ) {
			\WP_CLI::error( sprintf( 'Unsupported format "%s". Allowed: %s.', $format, implode( ', ', $allowed ) ) );
		}

		return $format;
	}

	/**
	 * @param array<int, array<string, mixed>> $rows
	 * @param array<int, string>               $fields
	 */
	protected function render_rows( array $rows, array $fields, string $format ): void {
		if ( 'json' === $format ) {
			\WP_CLI::line( (string) wp_json_encode( $rows, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
			return;
		}

		\WP_CLI\Utils\format_items( $format, $rows, $fields );
	}

	/**
	 * @param array<string, mixed> $data
	 */
	protected function render_assoc( array $data, string $format ): void {
		if ( 'json' === $format ) {
			\WP_CLI::line( (string) wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
			return;
		}

		$rows = array();
		foreach ( $data as $key => $value ) {
			$rows[] = array(
				'key' => (string) $key,
				'value' => $this->stringify_value( $value ),
			);
		}

		\WP_CLI\Utils\format_items( $format, $rows, array( 'key', 'value' ) );
	}

	/**
	 * @param array<string, mixed> $assoc_args
	 * @return array{blog_id: int|null, network: bool}
	 */
	protected function resolve_scope_args( array $assoc_args, bool $allow_network = false, bool $require_explicit_in_multisite = false ): array {
		$blog_id = isset( $assoc_args['blog-id'] ) ? (int) $assoc_args['blog-id'] : ( isset( $assoc_args['blog_id'] ) ? (int) $assoc_args['blog_id'] : null );
		$network = ! empty( $assoc_args['network'] );

		if ( $blog_id && $network ) {
			\WP_CLI::error( 'Use either --blog-id=<id> or --network, not both.' );
		}

		if ( $allow_network && $network && ! is_multisite() ) {
			\WP_CLI::error( '--network is only available in Multisite.' );
		}

		if ( $require_explicit_in_multisite && is_multisite() && ! $network && ! $blog_id ) {
			if ( $allow_network ) {
				\WP_CLI::error( 'Specify --blog-id=<id> or --network in Multisite.' );
			}

			\WP_CLI::error( 'Specify --blog-id=<id> in Multisite.' );
		}

		return array(
			'blog_id' => $blog_id,
			'network' => $network,
		);
	}

	/**
	 * @template T
	 * @param callable():T $callback
	 * @return T
	 */
	protected function with_blog( ?int $blog_id, callable $callback ): mixed {
		if ( ! is_multisite() || empty( $blog_id ) || get_current_blog_id() === $blog_id ) {
			return $callback();
		}

		switch_to_blog( $blog_id );
		try {
			return $callback();
		} finally {
			restore_current_blog();
		}
	}

	protected function resolve_user( string $identifier ): \WP_User {
		$identifier = trim( $identifier );

		$user = ctype_digit( $identifier )
			? get_user_by( 'id', (int) $identifier )
			: get_user_by( 'login', $identifier );

		if ( ! ( $user instanceof \WP_User ) && is_email( $identifier ) ) {
			$user = get_user_by( 'email', $identifier );
		}

		if ( ! ( $user instanceof \WP_User ) ) {
			\WP_CLI::error( sprintf( 'User "%s" not found.', $identifier ) );
		}

		return $user;
	}

	protected function mask_identifier( string $value ): string {
		$value = trim( $value );

		if ( '' === $value ) {
			return '';
		}

		$length = strlen( $value );
		if ( $length <= 4 ) {
			return substr( $value, 0, 1 ) . str_repeat( '*', max( 0, $length - 2 ) ) . substr( $value, -1 );
		}

		if ( $length <= 8 ) {
			return substr( $value, 0, 2 ) . '...' . substr( $value, -2 );
		}

		return substr( $value, 0, 3 ) . '...' . substr( $value, -3 );
	}

	protected function format_timestamp( int|string $timestamp ): string {
		$timestamp = (int) $timestamp;

		if ( $timestamp <= 0 ) {
			return '';
		}

		return gmdate( 'c', $timestamp );
	}

	/**
	 * @param array<int> $user_ids
	 */
	protected function aggregate_passkey_summaries( array $user_ids, ?int $blog_id = null ): array {
		return $this->with_blog(
			$blog_id,
			static function () use ( $user_ids ): array {
				$summaries = \EnterpriseAuth\Plugin\CredentialRepository::passkey_summaries_for_users( $user_ids );
				$aggregate = array(
					'total' => 0,
					'compliant' => 0,
					'legacy_non_compliant' => 0,
					'latest_last_used_at' => 0,
				);

				foreach ( $summaries as $summary ) {
					$aggregate['total'] += (int) ( $summary['total'] ?? 0 );
					$aggregate['compliant'] += (int) ( $summary['compliant'] ?? 0 );
					$aggregate['legacy_non_compliant'] += (int) ( $summary['legacy_non_compliant'] ?? 0 );

					$last_used = strtotime( (string) ( $summary['last_used_at'] ?? '' ) . ' UTC' );
					if ( false !== $last_used ) {
						$aggregate['latest_last_used_at'] = max( $aggregate['latest_last_used_at'], (int) $last_used );
					}
				}

				return $aggregate;
			}
		);
	}

	/**
	 * @return array<int>
	 */
	protected function site_user_ids( ?int $blog_id = null ): array {
		return $this->with_blog(
			$blog_id,
			static function (): array {
				return array_map(
					'intval',
					get_users(
						array(
							'fields' => 'ids',
							'blog_id' => get_current_blog_id(),
						)
					)
				);
			}
		);
	}

	/**
	 * @param array<string, mixed> $assoc_args
	 */
	protected function read_settings_payload( array $assoc_args ): array {
		$scope = $this->resolve_scope_args( $assoc_args, true, is_multisite() );

		if ( $scope['network'] ) {
			return SettingsController::read_network_settings_payload();
		}

		return $this->with_blog(
			$scope['blog_id'],
			static fn(): array => SettingsController::read()
		);
	}

	protected function stringify_value( mixed $value ): string {
		if ( is_bool( $value ) ) {
			return $value ? 'true' : 'false';
		}

		if ( is_scalar( $value ) || null === $value ) {
			return (string) $value;
		}

		return (string) wp_json_encode( $value, JSON_UNESCAPED_SLASHES );
	}

	protected function identity_label( string $identity_source ): string {
		return match ( $identity_source ) {
			'sso' => 'SSO',
			'scim' => 'SCIM',
			'mixed' => 'SSO + SCIM history',
			default => 'Local',
		};
	}
}