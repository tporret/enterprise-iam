<?php

declare( strict_types=1 );

namespace {
	if ( ! defined( 'ABSPATH' ) ) {
		define( 'ABSPATH', __DIR__ );
	}
	if ( ! defined( 'OBJECT' ) ) {
		define( 'OBJECT', 'OBJECT' );
	}

	class WP_Post {
		public int $ID;
		public string $post_name;
		public string $post_status;
		public string $post_type;

		public function __construct( int $id, string $post_name, string $post_status, string $post_type ) {
			$this->ID          = $id;
			$this->post_name   = $post_name;
			$this->post_status = $post_status;
			$this->post_type   = $post_type;
		}
	}

	$GLOBALS['ea_access_gate_posts'] = array(
		new WP_Post( 42, 'private-report', 'private', 'report' ),
	);

	function get_queried_object(): mixed {
		return null;
	}

	function get_query_var( string $key ): mixed {
		return '';
	}

	function get_post( int $post_id ): ?WP_Post {
		foreach ( $GLOBALS['ea_access_gate_posts'] as $post ) {
			if ( $post instanceof WP_Post && $post_id === $post->ID ) {
				return $post;
			}
		}

		return null;
	}

	function get_post_status( mixed $post ): string {
		return $post instanceof WP_Post ? $post->post_status : '';
	}

	function get_post_types( array $args = array(), string $output = 'names' ): array {
		if ( ! empty( $args['public'] ) || ! empty( $args['publicly_queryable'] ) ) {
			return array( 'post' => 'post', 'page' => 'page', 'report' => 'report' );
		}

		return array();
	}

	function get_page_by_path( string $page_path, string $output = OBJECT, array|string $post_type = 'page' ): ?WP_Post {
		$post_types = (array) $post_type;
		$slug       = basename( trim( $page_path, '/' ) );

		foreach ( $GLOBALS['ea_access_gate_posts'] as $post ) {
			if ( $post instanceof WP_Post && $slug === $post->post_name && in_array( $post->post_type, $post_types, true ) ) {
				return $post;
			}
		}

		return null;
	}

	function get_posts( array $args = array() ): array {
		return array();
	}

	function sanitize_title( mixed $value ): string {
		return is_string( $value ) ? strtolower( trim( $value ) ) : '';
	}

	function url_to_postid( string $url ): int {
		return 0;
	}

	function wp_parse_url( string $url, int $component = -1 ): mixed {
		return parse_url( $url, $component );
	}

	function home_url( string $path = '' ): string {
		return 'https://example.test/' . ltrim( $path, '/' );
	}

	function is_ssl(): bool {
		return true;
	}

	function wp_unslash( mixed $value ): mixed {
		return $value;
	}

	function esc_url_raw( mixed $value ): string {
		return is_string( $value ) ? $value : '';
	}
}

namespace EnterpriseAuth\Plugin {
	class SettingsController {
		public static function read(): array {
			return array( 'private_content_login_required' => true );
		}
	}
}

namespace {
	require_once __DIR__ . '/../../src/php/AccessGate.php';

	$_SERVER['HTTP_HOST']   = 'example.test';
	$_SERVER['REQUEST_URI'] = '/resources/private-report/';

	$gate   = new EnterpriseAuth\Plugin\AccessGate();
	$method = new ReflectionMethod( $gate, 'resolve_requested_post' );
	$method->setAccessible( true );

	$post = $method->invoke( $gate );

	if ( ! $post instanceof WP_Post ) {
		fwrite( STDERR, "FAIL: Expected path fallback to resolve private custom post type request.\n" );
		exit( 1 );
	}

	if ( 42 !== $post->ID ) {
		fwrite( STDERR, "FAIL: Resolved unexpected post ID.\n" );
		exit( 1 );
	}

	fwrite( STDOUT, "PASS: Access gate resolves private content from 404-style request path fallback.\n" );
}