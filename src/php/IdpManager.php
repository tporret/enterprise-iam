<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages Identity Provider (IdP) configurations stored in wp_options.
 *
 * Each IdP entry contains:
 *  - id            (string, unique UUID)
 *  - provider_name (string)
 *  - protocol      ('oidc' | 'saml')
 *  - client_id / entity_id
 *  - client_secret / certificate
 *  - authorization_endpoint / sso_url
 *  - token_endpoint (OIDC only)
 *  - userinfo_endpoint (OIDC only)
 *  - domain_mapping (string[])
 *  - role_mapping   (array<string,string>)  IdP group → WP role
 *  - super_tenant   (bool)                  Allows privileged role assignment
 *  - enabled        (bool)
 */
final class IdpManager {

	private const URL_FIELDS              = array(
		'issuer',
		'authorization_endpoint',
		'token_endpoint',
		'userinfo_endpoint',
		'jwks_uri',
		'sso_url',
		'end_session_endpoint',
		'slo_url',
	);
	private const OIDC_RUNTIME_URL_FIELDS = array(
		'issuer',
		'authorization_endpoint',
		'token_endpoint',
		'userinfo_endpoint',
		'jwks_uri',
	);
	private const URL_LABELS              = array(
		'issuer'                 => 'Issuer URL',
		'authorization_endpoint' => 'Authorization Endpoint',
		'token_endpoint'         => 'Token Endpoint',
		'userinfo_endpoint'      => 'UserInfo Endpoint',
		'jwks_uri'               => 'JWKS URI',
		'sso_url'                => 'SSO URL',
		'end_session_endpoint'   => 'End Session Endpoint',
		'slo_url'                => 'Single Logout URL',
		'runtime_endpoint'       => 'Runtime endpoint',
	);

	// ── Read ────────────────────────────────────────────────────────────────

	/**
	 * Return all IdP configurations.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function all(): array {
		return self::repository_manager()->all();
	}

	/**
	 * Find a single IdP by its id.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function find( string $id ): ?array {
		return self::repository_manager()->find( $id );
	}

	/**
	 * Find the first enabled IdP whose domain_mapping contains $domain.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function find_by_domain( string $domain ): ?array {
		return self::repository_manager()->findByDomain( $domain );
	}

	// ── Write ───────────────────────────────────────────────────────────────

	/**
	 * Save/update an IdP configuration. Inserts if new id, updates if existing.
	 *
	 * @param array<string, mixed> $idp
	 * @return true|\WP_Error
	 */
	public static function save( array $idp ) {
		return self::repository_manager()->save( $idp );
	}

	/**
	 * Delete an IdP configuration by id.
	 */
	public static function delete( string $id ): bool {
		return self::repository_manager()->delete( $id );
	}

	private static function repository_manager(): IdpRepositoryManager {
		return new IdpRepositoryManager( new SiteIdpAdapter() );
	}

	// ── Sanitization ────────────────────────────────────────────────────────

	/**
	 * Sanitize a raw IdP configuration array from the REST API.
	 *
	 * @param array<string, mixed> $raw
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function sanitize( array $raw ): array|\WP_Error {
		$protocol = in_array( $raw['protocol'] ?? '', array( 'oidc', 'saml' ), true )
			? $raw['protocol']
			: 'oidc';

		$domain_mapping = array();
		if ( ! empty( $raw['domain_mapping'] ) && is_array( $raw['domain_mapping'] ) ) {
			foreach ( $raw['domain_mapping'] as $d ) {
				$clean = sanitize_text_field( (string) $d );
				if ( '' !== $clean ) {
					$domain_mapping[] = strtolower( $clean );
				}
			}
		}

		$role_mapping = array();
		if ( ! empty( $raw['role_mapping'] ) && is_array( $raw['role_mapping'] ) ) {
			foreach ( $raw['role_mapping'] as $group => $role ) {
				$g = sanitize_text_field( (string) $group );
				$r = sanitize_text_field( (string) $role );
				if ( '' !== $g && '' !== $r ) {
					$role_mapping[ $g ] = $r;
				}
			}
		}

		$sanitized = array(
			'id'                         => ! empty( $raw['id'] ) ? sanitize_text_field( $raw['id'] ) : wp_generate_uuid4(),
			'provider_name'              => sanitize_text_field( $raw['provider_name'] ?? '' ),
			'provider_family'            => sanitize_key( (string) ( $raw['provider_family'] ?? '' ) ),
			'protocol'                   => $protocol,
			'client_id'                  => sanitize_text_field( $raw['client_id'] ?? '' ),
			'client_secret'              => sanitize_text_field( $raw['client_secret'] ?? '' ),
			'issuer'                     => esc_url_raw( $raw['issuer'] ?? '' ),
			'entity_id'                  => sanitize_text_field( $raw['entity_id'] ?? '' ),
			'certificate'                => sanitize_textarea_field( $raw['certificate'] ?? '' ),
			'authorization_endpoint'     => esc_url_raw( $raw['authorization_endpoint'] ?? '' ),
			'token_endpoint'             => esc_url_raw( $raw['token_endpoint'] ?? '' ),
			'userinfo_endpoint'          => esc_url_raw( $raw['userinfo_endpoint'] ?? '' ),
			'jwks_uri'                   => esc_url_raw( $raw['jwks_uri'] ?? '' ),
			'sso_url'                    => esc_url_raw( $raw['sso_url'] ?? '' ),
			'domain_mapping'             => $domain_mapping,
			'role_mapping'               => $role_mapping,
			'super_tenant'               => ! empty( $raw['super_tenant'] ),
			'enabled'                    => ! empty( $raw['enabled'] ),
			'override_attribute_mapping' => ! empty( $raw['override_attribute_mapping'] ),
			'custom_email_attr'          => sanitize_text_field( $raw['custom_email_attr'] ?? '' ),
			'custom_first_name_attr'     => sanitize_text_field( $raw['custom_first_name_attr'] ?? '' ),
			'custom_last_name_attr'      => sanitize_text_field( $raw['custom_last_name_attr'] ?? '' ),
			'force_reauth'               => ! empty( $raw['force_reauth'] ),
			'end_session_endpoint'       => esc_url_raw( $raw['end_session_endpoint'] ?? '' ),
			'slo_url'                    => esc_url_raw( $raw['slo_url'] ?? '' ),
		);

		$url_validation = self::validate_configured_urls( $sanitized );
		if ( is_wp_error( $url_validation ) ) {
			return $url_validation;
		}

		return $sanitized;
	}

	/**
	 * Validate OIDC runtime endpoints before any server-side outbound requests.
	 *
	 * @param array<string, mixed> $idp
	 * @return true|\WP_Error
	 */
	public static function validate_runtime_oidc_configuration( array $idp ) {
		return self::validate_configured_urls( $idp, self::OIDC_RUNTIME_URL_FIELDS );
	}

	/**
	 * Validate a single runtime endpoint URL.
	 *
	 * @return true|\WP_Error
	 */
	public static function validate_runtime_endpoint_url( string $url, string $field ) {
		return self::validate_endpoint_url( $url, $field );
	}

	/**
	 * Build a pinned cURL resolution target for a validated runtime endpoint.
	 *
	 * @return array{host: string, port: int, resolve: ?string}|\WP_Error
	 */
	public static function build_runtime_curl_resolve_target( string $url, string $field = 'runtime_endpoint' ) {
		$validation = self::validate_endpoint_url( $url, $field );
		if ( is_wp_error( $validation ) ) {
			return $validation;
		}

		$validated = wp_http_validate_url( $url );
		if ( false === $validated ) {
			return new \WP_Error(
				'enterprise_auth_invalid_idp_url',
				'Runtime endpoint must be a valid HTTPS URL.',
				array( 'status' => 400 )
			);
		}

		$host = strtolower( (string) wp_parse_url( $validated, PHP_URL_HOST ) );
		$port = (int) wp_parse_url( $validated, PHP_URL_PORT );
		if ( $port <= 0 ) {
			$port = 443;
		}

		if ( false !== filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return array(
				'host'    => $host,
				'port'    => $port,
				'resolve' => null,
			);
		}

		$resolved_ips = self::resolve_host_ips( $host );
		if ( empty( $resolved_ips ) ) {
			return new \WP_Error(
				'enterprise_auth_invalid_idp_url',
				'Runtime endpoint must resolve to a public IP address.',
				array( 'status' => 400 )
			);
		}

		$resolve_ips = array_map(
			static function ( string $ip ): string {
				return str_contains( $ip, ':' ) ? '[' . $ip . ']' : $ip;
			},
			$resolved_ips
		);

		return array(
			'host'    => $host,
			'port'    => $port,
			'resolve' => sprintf( '%s:%d:%s', $host, $port, implode( ',', $resolve_ips ) ),
		);
	}

	/**
	 * Validate configured public HTTPS URLs and reject internal targets.
	 *
	 * @param array<string, mixed> $idp
	 * @param string[]|null        $fields
	 * @return true|\WP_Error
	 */
	private static function validate_configured_urls( array $idp, ?array $fields = null ) {
		$fields = is_array( $fields ) ? $fields : self::URL_FIELDS;

		foreach ( $fields as $field ) {
			$validation = self::validate_endpoint_url( (string) ( $idp[ $field ] ?? '' ), $field );
			if ( is_wp_error( $validation ) ) {
				return $validation;
			}
		}

		return true;
	}

	/**
	 * Validate a configured IdP URL.
	 *
	 * @return true|\WP_Error
	 */
	private static function validate_endpoint_url( string $url, string $field ) {
		if ( '' === $url ) {
			return true;
		}

		$label  = self::URL_LABELS[ $field ] ?? 'Configured URL';
		$scheme = strtolower( (string) wp_parse_url( $url, PHP_URL_SCHEME ) );

		if ( 'https' !== $scheme ) {
			return new \WP_Error(
				'enterprise_auth_invalid_idp_url',
				sprintf( '%s must use https://.', $label ),
				array( 'status' => 400 )
			);
		}

		$validated = wp_http_validate_url( $url );
		if ( false === $validated ) {
			return new \WP_Error(
				'enterprise_auth_invalid_idp_url',
				sprintf( '%s must be a valid HTTPS URL.', $label ),
				array( 'status' => 400 )
			);
		}

		$host = strtolower( (string) wp_parse_url( $validated, PHP_URL_HOST ) );
		if ( '' === $host ) {
			return new \WP_Error(
				'enterprise_auth_invalid_idp_url',
				sprintf( '%s must include a hostname.', $label ),
				array( 'status' => 400 )
			);
		}

		if ( 'localhost' === $host ) {
			return new \WP_Error(
				'enterprise_auth_invalid_idp_url',
				sprintf( '%s cannot target localhost or internal network addresses.', $label ),
				array( 'status' => 400 )
			);
		}

		$resolved_ips = self::resolve_host_ips( $host );
		if ( empty( $resolved_ips ) ) {
			return new \WP_Error(
				'enterprise_auth_invalid_idp_url',
				sprintf( '%s must resolve to a public IP address.', $label ),
				array( 'status' => 400 )
			);
		}

		foreach ( $resolved_ips as $ip ) {
			if ( self::is_blocked_ip( $ip ) ) {
				return new \WP_Error(
					'enterprise_auth_invalid_idp_url',
					sprintf( '%s cannot target private, loopback, link-local, or metadata addresses.', $label ),
					array( 'status' => 400 )
				);
			}
		}

		return true;
	}

	/**
	 * Resolve a hostname into IPv4/IPv6 addresses.
	 *
	 * @return string[]
	 */
	private static function resolve_host_ips( string $host ): array {
		if ( false !== filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return array( $host );
		}

		$ips = array();

		$ipv4 = gethostbynamel( $host );
		if ( false !== $ipv4 && is_array( $ipv4 ) ) {
			$ips = array_merge( $ips, $ipv4 );
		}

		if ( function_exists( 'dns_get_record' ) && defined( 'DNS_AAAA' ) ) {
			$records = dns_get_record( $host, DNS_AAAA );
			if ( is_array( $records ) ) {
				foreach ( $records as $record ) {
					if ( ! empty( $record['ipv6'] ) ) {
						$ips[] = $record['ipv6'];
					}
				}
			}
		}

		$ips = array_filter(
			array_unique( $ips ),
			static fn( string $ip ): bool => false !== filter_var( $ip, FILTER_VALIDATE_IP )
		);

		return array_values( $ips );
	}

	/**
	 * Reject loopback, private, link-local, and metadata targets.
	 */
	private static function is_blocked_ip( string $ip ): bool {
		if ( '169.254.169.254' === $ip ) {
			return true;
		}

		if ( '::1' === $ip || str_starts_with( $ip, '127.' ) ) {
			return true;
		}

		return false === filter_var(
			$ip,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
		);
	}
}
