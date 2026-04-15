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

	/**
	 * Read transient value and delete it in one place for consistent semantics.
	 *
	 * @return mixed|null
	 */
	public static function consume( string $key ) {
		$value = get_transient( $key );
		if ( false === $value || null === $value ) {
			return null;
		}

		delete_transient( $key );

		return $value;
	}
}
