<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shared helper for single-use transient values.
 */
final class OneTimeTransient {

	private const LOCK_TTL = 30;

	/**
	 * Read transient value and delete it while holding a short-lived process lock.
	 *
	 * @return mixed|null
	 */
	public static function consume( string $key ) {
		$lock_option = self::lock_option_name( $key );
		if ( ! self::acquire_lock( $lock_option ) ) {
			return null;
		}

		try {
			$value = get_transient( $key );
			if ( false === $value || null === $value ) {
				return null;
			}

			delete_transient( $key );

			return $value;
		} finally {
			delete_option( $lock_option );
		}
	}

	private static function acquire_lock( string $lock_option ): bool {
		$expires = time() + self::LOCK_TTL;
		if ( add_option( $lock_option, (string) $expires, '', 'no' ) ) {
			return true;
		}

		$existing = (int) get_option( $lock_option, 0 );
		if ( $existing > time() ) {
			return false;
		}

		delete_option( $lock_option );

		return add_option( $lock_option, (string) $expires, '', 'no' );
	}

	private static function lock_option_name( string $key ): string {
		return 'ea_one_time_lock_' . md5( $key );
	}
}
