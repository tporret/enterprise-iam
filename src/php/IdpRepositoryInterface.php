<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

interface IdpRepositoryInterface {

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public function readAllRaw(): array;

	/**
	 * @param array<int, array<string, mixed>> $idps
	 */
	public function writeAll( array $idps ): void;
}
