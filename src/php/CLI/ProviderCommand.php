<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin\CLI;

use EnterpriseAuth\Plugin\CurrentSiteIdpManager;
use EnterpriseAuth\Plugin\IdpManager;
use EnterpriseAuth\Plugin\NetworkIdpManager;
use EnterpriseAuth\Plugin\NetworkMode;
use EnterpriseAuth\Plugin\SiteAssignmentManager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ProviderCommand extends BaseCommand {

	/**
	 * List identity providers.
	 *
	 * @subcommand list
	 *
	 * ## OPTIONS
	 *
	 * [--blog-id=<id>]
	 * : Inspect providers visible to a site context.
	 *
	 * [--network]
	 * : Inspect network-managed providers.
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 */
	public function list_( array $_args, array $assoc_args ): void {
		$format = $this->get_format( $assoc_args );
		$rows   = array_map( array( $this, 'summarize_provider' ), $this->providers_for_scope( $assoc_args ) );

		$this->render_rows(
			$rows,
			array( 'id', 'provider_name', 'protocol', 'provider_family', 'enabled', 'domain_mapping_count', 'role_mapping_count', 'super_tenant', 'storage_scope', 'assignment_count' ),
			$format
		);
	}

	/**
	 * Show one identity provider.
	 */
	public function show( array $args, array $assoc_args ): void {
		$format   = $this->get_format( $assoc_args, array( 'table', 'json' ) );
		$provider = $this->provider_by_id( (string) ( $args[0] ?? '' ), $assoc_args );
		$summary  = $this->summarize_provider( $provider );
		$details  = array_merge(
			$summary,
			array(
				'domain_mapping' => array_values( (array) ( $provider['domain_mapping'] ?? array() ) ),
				'role_mapping' => (array) ( $provider['role_mapping'] ?? array() ),
				'has_client_secret' => '' !== (string) ( $provider['client_secret'] ?? '' ),
				'client_secret_masked' => '' !== (string) ( $provider['client_secret'] ?? '' ) ? $this->mask_identifier( (string) $provider['client_secret'] ) : '',
			)
		);

		$this->render_assoc( $details, $format );
	}

	/**
	 * Validate one identity provider.
	 */
	public function validate( array $args, array $assoc_args ): void {
		$format   = $this->get_format( $assoc_args, array( 'table', 'json' ) );
		$provider = $this->provider_by_id( (string) ( $args[0] ?? '' ), $assoc_args );
		$report   = $this->validation_report( $provider );

		$this->render_assoc( $report, $format );

		if ( ! empty( $report['valid'] ) ) {
			\WP_CLI::success( sprintf( 'Provider %s validated successfully.', (string) ( $provider['id'] ?? '' ) ) );
			return;
		}

		\WP_CLI::warning( sprintf( 'Provider %s has validation issues.', (string) ( $provider['id'] ?? '' ) ) );
	}

	/**
	 * Show domain mappings for one provider.
	 */
	public function domains( array $args, array $assoc_args ): void {
		$format   = $this->get_format( $assoc_args );
		$provider = $this->provider_by_id( (string) ( $args[0] ?? '' ), $assoc_args );
		$rows     = array();

		foreach ( (array) ( $provider['domain_mapping'] ?? array() ) as $domain ) {
			$rows[] = array(
				'provider_id' => (string) ( $provider['id'] ?? '' ),
				'domain' => (string) $domain,
			);
		}

		$this->render_rows( $rows, array( 'provider_id', 'domain' ), $format );
	}

	/**
	 * @param array<string, mixed> $assoc_args
	 * @return array<int, array<string, mixed>>
	 */
	private function providers_for_scope( array $assoc_args ): array {
		$scope = $this->resolve_scope_args( $assoc_args, true, NetworkMode::is_network_mode() );

		if ( $scope['network'] ) {
			return NetworkIdpManager::all();
		}

		return $this->with_blog(
			$scope['blog_id'],
			static function (): array {
				if ( NetworkMode::is_network_mode() ) {
					return CurrentSiteIdpManager::all();
				}

				return IdpManager::all();
			}
		);
	}

	/**
	 * @param array<string, mixed> $assoc_args
	 * @return array<string, mixed>
	 */
	private function provider_by_id( string $id, array $assoc_args ): array {
		foreach ( $this->providers_for_scope( $assoc_args ) as $provider ) {
			if ( (string) ( $provider['id'] ?? '' ) === $id ) {
				return $provider;
			}
		}

		\WP_CLI::error( sprintf( 'Provider "%s" not found in the requested scope.', $id ) );
	}

	/**
	 * @param array<string, mixed> $provider
	 * @return array<string, mixed>
	 */
	private function summarize_provider( array $provider ): array {
		$storage_scope = NetworkMode::is_network_mode() && null !== NetworkIdpManager::find( (string) ( $provider['id'] ?? '' ) )
			? 'network'
			: 'site';

		return array(
			'id' => (string) ( $provider['id'] ?? '' ),
			'provider_name' => (string) ( $provider['provider_name'] ?? '' ),
			'protocol' => (string) ( $provider['protocol'] ?? '' ),
			'provider_family' => (string) ( $provider['provider_family'] ?? '' ),
			'enabled' => ! empty( $provider['enabled'] ) ? 'yes' : 'no',
			'domain_mapping_count' => count( (array) ( $provider['domain_mapping'] ?? array() ) ),
			'role_mapping_count' => count( (array) ( $provider['role_mapping'] ?? array() ) ),
			'super_tenant' => ! empty( $provider['super_tenant'] ) ? 'yes' : 'no',
			'storage_scope' => $storage_scope,
			'assignment_count' => NetworkMode::is_network_mode() ? SiteAssignmentManager::count_sites_for_idp( (string) ( $provider['id'] ?? '' ) ) : 0,
		);
	}

	/**
	 * @param array<string, mixed> $provider
	 * @return array<string, mixed>
	 */
	private function validation_report( array $provider ): array {
		$errors = array();

		if ( '' === (string) ( $provider['provider_name'] ?? '' ) ) {
			$errors[] = 'provider_name is required';
		}

		if ( 'oidc' === ( $provider['protocol'] ?? '' ) ) {
			foreach ( array( 'issuer', 'client_id', 'client_secret', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri' ) as $field ) {
				if ( '' === (string) ( $provider[ $field ] ?? '' ) ) {
					$errors[] = sprintf( '%s is required for OIDC providers', $field );
				}
			}

			$url_validation = IdpManager::validate_runtime_oidc_configuration( $provider );
			if ( is_wp_error( $url_validation ) ) {
				$errors[] = $url_validation->get_error_message();
			}
		} else {
			foreach ( array( 'entity_id', 'sso_url', 'certificate' ) as $field ) {
				if ( '' === (string) ( $provider[ $field ] ?? '' ) ) {
					$errors[] = sprintf( '%s is required for SAML providers', $field );
				}
			}

			$sanitized = IdpManager::sanitize( $provider );
			if ( is_wp_error( $sanitized ) ) {
				$errors[] = $sanitized->get_error_message();
			}
		}

		return array(
			'id' => (string) ( $provider['id'] ?? '' ),
			'protocol' => (string) ( $provider['protocol'] ?? '' ),
			'valid' => array() === $errors,
			'errors' => $errors,
		);
	}
}