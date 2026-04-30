<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class IdpRepositoryManager {

	public function __construct(
		private IdpRepositoryInterface $repository,
		private string $storageLabel = ''
	) {
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public function all(): array {
		$all = $this->repository->readAllRaw();

		foreach ( $all as &$idp ) {
			if ( isset( $idp['client_secret'] ) ) {
				$idp['client_secret'] = Encryption::decrypt( $idp['client_secret'] );
			}
		}
		unset( $idp );

		return $all;
	}

	public function hasAny(): bool {
		return count( $this->repository->readAllRaw() ) > 0;
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public function find( string $id ): ?array {
		foreach ( $this->all() as $idp ) {
			if ( ( $idp['id'] ?? '' ) === $id ) {
				return $idp;
			}
		}

		return null;
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public function findByDomain( string $domain ): ?array {
		$domain = strtolower( trim( $domain ) );

		foreach ( $this->all() as $idp ) {
			if ( empty( $idp['enabled'] ) ) {
				continue;
			}

			$domains = array_map( 'strtolower', (array) ( $idp['domain_mapping'] ?? array() ) );
			if ( in_array( $domain, $domains, true ) ) {
				return $idp;
			}
		}

		return null;
	}

	/**
	 * @param array<string, mixed> $idp
	 * @return true|\WP_Error
	 */
	public function save( array $idp ) {
		try {
			if ( isset( $idp['client_secret'] ) && '' !== $idp['client_secret'] ) {
				$idp['client_secret'] = Encryption::encrypt( $idp['client_secret'] );
			}
		} catch ( \RuntimeException $e ) {
			$idp_id = sanitize_text_field( (string) ( $idp['id'] ?? '' ) );
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log(
				sprintf(
					'CRITICAL: Enterprise IAM failed to encrypt %sclient_secret for IdP "%s": %s',
					'' !== $this->storageLabel ? $this->storageLabel . ' ' : '',
					$idp_id,
					$e->getMessage()
				)
			);

			return new \WP_Error(
				'enterprise_auth_secret_storage_failed',
				'Failed to save IdP configuration securely. Please contact your administrator.',
				array( 'status' => 500 )
			);
		}

		$all   = $this->repository->readAllRaw();
		$found = false;

		foreach ( $all as $index => $existing ) {
			if ( ( $existing['id'] ?? '' ) === ( $idp['id'] ?? '' ) ) {
				$all[ $index ] = $idp;
				$found         = true;
				break;
			}
		}

		if ( ! $found ) {
			$all[] = $idp;
		}

		$this->repository->writeAll( $all );

		return true;
	}

	public function delete( string $id ): bool {
		$all      = $this->repository->readAllRaw();
		$filtered = array_filter( $all, static fn( array $idp ) => ( $idp['id'] ?? '' ) !== $id );

		if ( count( $filtered ) === count( $all ) ) {
			return false;
		}

		$this->repository->writeAll( array_values( $filtered ) );

		return true;
	}
}
