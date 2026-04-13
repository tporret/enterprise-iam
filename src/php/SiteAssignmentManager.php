<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SiteAssignmentManager {

	private const OPTION_KEY = 'enterprise_auth_site_assignments';

	/**
	 * @return array{assigned_idp_ids: string[], primary_idp_id: string}
	 */
	public static function read_for_current_site(): array {
		return self::read_for_blog( get_current_blog_id() );
	}

	/**
	 * @return array{assigned_idp_ids: string[], primary_idp_id: string}
	 */
	public static function read_for_blog( int $blog_id ): array {
		$raw = self::with_blog(
			$blog_id,
			static fn(): mixed => get_option( self::OPTION_KEY, array() )
		);

		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		$assigned_ids = array();
		foreach ( (array) ( $raw['assigned_idp_ids'] ?? array() ) as $idp_id ) {
			$idp_id = sanitize_text_field( (string) $idp_id );
			if ( '' !== $idp_id ) {
				$assigned_ids[] = $idp_id;
			}
		}

		$assigned_ids = array_values( array_unique( $assigned_ids ) );
		$primary_idp  = sanitize_text_field( (string) ( $raw['primary_idp_id'] ?? '' ) );

		if ( '' !== $primary_idp && ! in_array( $primary_idp, $assigned_ids, true ) ) {
			$primary_idp = '';
		}

		return array(
			'assigned_idp_ids' => $assigned_ids,
			'primary_idp_id'   => $primary_idp,
		);
	}

	/**
	 * @param array<string, mixed> $assignment
	 * @return array{assigned_idp_ids: string[], primary_idp_id: string}
	 */
	public static function save_for_blog( int $blog_id, array $assignment ): array {
		$sanitized = self::sanitize_assignment( $assignment );

		self::with_blog(
			$blog_id,
			static function () use ( $sanitized ): void {
				update_option( self::OPTION_KEY, $sanitized );
			}
		);

		return $sanitized;
	}

	public static function count_sites_for_idp( string $idp_id ): int {
		if ( ! is_multisite() ) {
			return 0;
		}

		$count = 0;
		foreach ( get_sites( array( 'number' => 0 ) ) as $site ) {
			$assignment = self::read_for_blog( (int) $site->blog_id );
			if ( in_array( $idp_id, $assignment['assigned_idp_ids'], true ) ) {
				++$count;
			}
		}

		return $count;
	}

	public static function remove_idp_references( string $idp_id ): void {
		if ( ! is_multisite() ) {
			return;
		}

		foreach ( get_sites( array( 'number' => 0 ) ) as $site ) {
			$blog_id    = (int) $site->blog_id;
			$assignment = self::read_for_blog( $blog_id );
			$remaining  = array_values(
				array_filter(
					$assignment['assigned_idp_ids'],
					static fn( string $assigned_id ): bool => $assigned_id !== $idp_id
				)
			);

			if ( $remaining === $assignment['assigned_idp_ids'] ) {
				continue;
			}

			self::save_for_blog(
				$blog_id,
				array(
					'assigned_idp_ids' => $remaining,
					'primary_idp_id'   => $assignment['primary_idp_id'] === $idp_id ? '' : $assignment['primary_idp_id'],
				)
			);
		}
	}

	/**
	 * @param array<string, mixed> $assignment
	 * @return array{assigned_idp_ids: string[], primary_idp_id: string}
	 */
	private static function sanitize_assignment( array $assignment ): array {
		$assigned_ids = array();
		foreach ( (array) ( $assignment['assigned_idp_ids'] ?? array() ) as $idp_id ) {
			$idp_id = sanitize_text_field( (string) $idp_id );
			if ( '' !== $idp_id && null !== NetworkIdpManager::find( $idp_id ) ) {
				$assigned_ids[] = $idp_id;
			}
		}

		$assigned_ids = array_values( array_unique( $assigned_ids ) );
		$primary_idp  = sanitize_text_field( (string) ( $assignment['primary_idp_id'] ?? '' ) );

		if ( '' !== $primary_idp && ! in_array( $primary_idp, $assigned_ids, true ) ) {
			$primary_idp = '';
		}

		return array(
			'assigned_idp_ids' => $assigned_ids,
			'primary_idp_id'   => $primary_idp,
		);
	}

	private static function with_blog( int $blog_id, callable $callback ): mixed {
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