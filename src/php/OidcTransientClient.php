<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;

/**
 * OpenID Connect client that uses an in-memory state bag during callback handling.
 */
final class OidcTransientClient extends OpenIDConnectClient {

	private const MAX_RUNTIME_REDIRECTS = 3;

	/**
	 * Session replacement storage consumed by the upstream library.
	 *
	 * @var array<string, mixed>
	 */
	private array $session_store = array();

	private ?string $http_proxy = null;

	private bool $verify_peer = true;

	private bool $verify_host = true;

	/**
	 * Prime the transient-backed state values required during callback handling.
	 *
	 * @param array<string, mixed> $session_store
	 */
	public function prime_session_store( array $session_store ): void {
		$this->session_store = $session_store;
	}

	public function setHttpProxy( string $http_proxy ) {
		$this->http_proxy = $http_proxy;
		parent::setHttpProxy( $http_proxy );
	}

	public function setVerifyPeer( bool $verify_peer ) {
		$this->verify_peer = $verify_peer;
		parent::setVerifyPeer( $verify_peer );
	}

	public function setVerifyHost( bool $verify_host ) {
		$this->verify_host = $verify_host;
		parent::setVerifyHost( $verify_host );
	}

	protected function startSession() {}

	protected function commitSession() {}

	protected function getSessionKey( string $key ) {
		return $this->session_store[ $key ] ?? false;
	}

	protected function setSessionKey( string $key, $value ) {
		$this->session_store[ $key ] = $value;
	}

	protected function unsetSessionKey( string $key ) {
		unset( $this->session_store[ $key ] );
	}

	/**
	 * Pin each outbound OIDC request to the public IPs resolved at request time.
	 *
	 * This prevents post-validation DNS rebinding and stops redirects from
	 * silently changing the trusted transport origin.
	 *
	 * @param string      $url
	 * @param string|null $post_body
	 * @param string[]    $headers
	 * @return bool|string
	 * @throws OpenIDConnectClientException
	 */
	// phpcs:disable WordPress.WP.AlternativeFunctions.curl_curl_init,WordPress.WP.AlternativeFunctions.curl_curl_setopt,WordPress.WP.AlternativeFunctions.curl_curl_exec,WordPress.WP.AlternativeFunctions.curl_curl_getinfo,WordPress.WP.AlternativeFunctions.curl_curl_errno,WordPress.WP.AlternativeFunctions.curl_curl_error,WordPress.WP.AlternativeFunctions.curl_curl_close
	protected function fetchURL( string $url, string $post_body = null, array $headers = array() ) {
		return $this->perform_runtime_request( $url, $post_body, $headers, 0 );
	}

	/**
	 * @param string|null $post_body
	 * @param string[]    $headers
	 * @return bool|string
	 * @throws OpenIDConnectClientException
	 */
	private function perform_runtime_request( string $url, ?string $post_body, array $headers, int $redirect_count ) {
		if ( $redirect_count > self::MAX_RUNTIME_REDIRECTS ) {
			throw new OpenIDConnectClientException( 'OIDC runtime request exceeded the redirect limit.' );
		}

		$transport = IdpManager::build_runtime_curl_resolve_target( $url );
		if ( is_wp_error( $transport ) ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Internal exception message for server-side logging only.
			throw new OpenIDConnectClientException( sanitize_text_field( $transport->get_error_message() ) );
		}

		$response_headers = array();
		$ch               = curl_init();

		if ( false === $ch ) {
			throw new OpenIDConnectClientException( 'Failed to initialize OIDC HTTP transport.' );
		}

		if ( null !== $post_body ) {
			curl_setopt( $ch, CURLOPT_CUSTOMREQUEST, 'POST' );
			curl_setopt( $ch, CURLOPT_POSTFIELDS, $post_body );

			$content_type = 'application/x-www-form-urlencoded';
			if ( is_object( json_decode( $post_body, false ) ) ) {
				$content_type = 'application/json';
			}

			$headers[] = "Content-Type: $content_type";
		}

		curl_setopt( $ch, CURLOPT_USERAGENT, $this->getUserAgent() );

		if ( ! empty( $headers ) ) {
			curl_setopt( $ch, CURLOPT_HTTPHEADER, $headers );
		}

		curl_setopt( $ch, CURLOPT_URL, $url );

		if ( null !== $this->http_proxy ) {
			curl_setopt( $ch, CURLOPT_PROXY, $this->http_proxy );
		}

		curl_setopt( $ch, CURLOPT_HEADER, false );
		curl_setopt(
			$ch,
			CURLOPT_HEADERFUNCTION,
			static function ( $curl_handle, string $header_line ) use ( &$response_headers ): int {
				$trimmed = trim( $header_line );

				if ( '' === $trimmed ) {
					return strlen( $header_line );
				}

				if ( 1 === preg_match( '/^HTTP\/\d(?:\.\d)?\s+\d+/', $trimmed ) ) {
					$response_headers = array();
					return strlen( $header_line );
				}

				if ( false !== strpos( $header_line, ':' ) ) {
					list( $name, $value )                              = explode( ':', $header_line, 2 );
					$response_headers[ strtolower( trim( $name ) ) ][] = trim( $value );
				}

				return strlen( $header_line );
			}
		);
		curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, false );

		$cert_path = $this->getCertPath();
		if ( null !== $cert_path ) {
			curl_setopt( $ch, CURLOPT_CAINFO, $cert_path );
		}

		curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, $this->verify_host ? 2 : 0 );
		curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, $this->verify_peer );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $ch, CURLOPT_TIMEOUT, $this->getTimeout() );

		if ( ! empty( $transport['resolve'] ) ) {
			curl_setopt( $ch, CURLOPT_RESOLVE, array( $transport['resolve'] ) );
		}

		$output       = curl_exec( $ch );
		$info         = curl_getinfo( $ch );
		$curl_errno   = curl_errno( $ch );
		$curl_error   = curl_error( $ch );
		$status_code  = (int) ( $info['http_code'] ?? 0 );
		$content_type = $info['content_type'] ?? null;

		curl_close( $ch );

		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Inherited vendor property name.
		$this->responseCode = $status_code;
		$this->set_parent_private_property( 'responseContentType', $content_type );

		if ( false === $output ) {
			// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Internal exception message for server-side logging only.
			throw new OpenIDConnectClientException(
				sprintf( 'Curl error: (%d) %s', absint( $curl_errno ), sanitize_text_field( $curl_error ) )
			);
			// phpcs:enable WordPress.Security.EscapeOutput.ExceptionNotEscaped
		}

		if ( $this->is_redirect_response( $status_code ) ) {
			$redirect_url = $this->resolve_redirect_url( $url, (string) ( $response_headers['location'][0] ?? '' ) );

			if ( null === $redirect_url ) {
				throw new OpenIDConnectClientException( 'OIDC runtime request returned an invalid redirect target.' );
			}

			if ( ! $this->is_allowed_redirect_target( $url, $redirect_url ) ) {
				throw new OpenIDConnectClientException( 'OIDC runtime request attempted to redirect to a different origin.' );
			}

			return $this->perform_runtime_request( $redirect_url, $post_body, $headers, $redirect_count + 1 );
		}

		return $output;
	}
	// phpcs:enable WordPress.WP.AlternativeFunctions.curl_curl_init,WordPress.WP.AlternativeFunctions.curl_curl_setopt,WordPress.WP.AlternativeFunctions.curl_curl_exec,WordPress.WP.AlternativeFunctions.curl_curl_getinfo,WordPress.WP.AlternativeFunctions.curl_curl_errno,WordPress.WP.AlternativeFunctions.curl_curl_error,WordPress.WP.AlternativeFunctions.curl_curl_close

	private function is_redirect_response( int $status_code ): bool {
		return in_array( $status_code, array( 301, 302, 303, 307, 308 ), true );
	}

	private function resolve_redirect_url( string $base_url, string $location ): ?string {
		$location = trim( $location );
		if ( '' === $location ) {
			return null;
		}

		$absolute = wp_http_validate_url( $location );
		if ( false !== $absolute ) {
			return $absolute;
		}

		$base = wp_parse_url( $base_url );
		if ( ! is_array( $base ) || empty( $base['scheme'] ) || empty( $base['host'] ) ) {
			return null;
		}

		$origin = strtolower( (string) $base['scheme'] ) . '://' . $base['host'];
		if ( isset( $base['port'] ) ) {
			$origin .= ':' . (int) $base['port'];
		}

		if ( str_starts_with( $location, '//' ) ) {
			$location = strtolower( (string) $base['scheme'] ) . ':' . $location;
		} elseif ( str_starts_with( $location, '/' ) ) {
			$location = $origin . $location;
		} elseif ( str_starts_with( $location, '?' ) ) {
			$location = $origin . (string) ( $base['path'] ?? '/' ) . $location;
		} elseif ( ! preg_match( '/^[a-z][a-z0-9+.-]*:/i', $location ) ) {
			$path      = (string) ( $base['path'] ?? '/' );
			$directory = preg_replace( '~/[^/]*$~', '/', $path );
			$location  = $origin . $directory . $location;
		}

		$validated = wp_http_validate_url( $location );
		return false !== $validated ? $validated : null;
	}

	private function is_allowed_redirect_target( string $source_url, string $target_url ): bool {
		$source = wp_parse_url( $source_url );
		$target = wp_parse_url( $target_url );

		if ( ! is_array( $source ) || ! is_array( $target ) ) {
			return false;
		}

		$source_scheme = strtolower( (string) ( $source['scheme'] ?? '' ) );
		$target_scheme = strtolower( (string) ( $target['scheme'] ?? '' ) );
		$source_host   = strtolower( (string) ( $source['host'] ?? '' ) );
		$target_host   = strtolower( (string) ( $target['host'] ?? '' ) );

		return 'https' === $target_scheme
			&& $source_scheme === $target_scheme
			&& $source_host === $target_host
			&& $this->normalize_port( $source ) === $this->normalize_port( $target );
	}

	/**
	 * @param array<string, mixed> $parts
	 */
	private function normalize_port( array $parts ): int {
		$port = (int) ( $parts['port'] ?? 0 );
		if ( $port > 0 ) {
			return $port;
		}

		return 'https' === strtolower( (string) ( $parts['scheme'] ?? '' ) ) ? 443 : 80;
	}

	private function set_parent_private_property( string $property, $value ): void {
		static $properties = array();

		if ( ! isset( $properties[ $property ] ) ) {
			$properties[ $property ] = new \ReflectionProperty( OpenIDConnectClient::class, $property );
			$properties[ $property ]->setAccessible( true );
		}

		$properties[ $property ]->setValue( $this, $value );
	}
}
