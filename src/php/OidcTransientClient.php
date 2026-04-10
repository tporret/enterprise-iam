<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Jumbojett\OpenIDConnectClient;

/**
 * OpenID Connect client that uses an in-memory state bag during callback handling.
 */
final class OidcTransientClient extends OpenIDConnectClient {

	/**
	 * Session replacement storage consumed by the upstream library.
	 *
	 * @var array<string, mixed>
	 */
	private array $session_store = array();

	/**
	 * Prime the transient-backed state values required during callback handling.
	 *
	 * @param array<string, mixed> $session_store
	 */
	public function prime_session_store( array $session_store ): void {
		$this->session_store = $session_store;
	}

	protected function startSession() {
		return;
	}

	protected function commitSession() {
		return;
	}

	protected function getSessionKey( string $key ) {
		return $this->session_store[ $key ] ?? false;
	}

	protected function setSessionKey( string $key, $value ) {
		$this->session_store[ $key ] = $value;
	}

	protected function unsetSessionKey( string $key ) {
		unset( $this->session_store[ $key ] );
	}
}