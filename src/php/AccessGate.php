<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AccessGate {

	public function init(): void {
		add_action( 'template_redirect', array( $this, 'maybe_gate_request' ), 1 );
	}

	public function maybe_gate_request(): void {
		if ( $this->should_bypass_request() ) {
			return;
		}

		if ( ! $this->private_content_gate_enabled() ) {
			return;
		}

		if ( ! $this->is_private_content_request() ) {
			return;
		}

		wp_safe_redirect( wp_login_url( $this->current_request_url() ) );
		exit;
	}

	private function should_bypass_request(): bool {
		if ( is_user_logged_in() || is_admin() || wp_doing_ajax() || wp_doing_cron() ) {
			return true;
		}

		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return true;
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}

		if ( is_feed() || is_robots() || is_trackback() ) {
			return true;
		}

		return false;
	}

	private function private_content_gate_enabled(): bool {
		$settings = SettingsController::read();

		return ! empty( $settings['private_content_login_required'] );
	}

	private function is_private_content_request(): bool {
		$post = $this->resolve_requested_post();

		return $post instanceof \WP_Post && 'private' === get_post_status( $post );
	}

	private function resolve_requested_post(): ?\WP_Post {
		$object = get_queried_object();
		if ( $object instanceof \WP_Post ) {
			return $object;
		}

		foreach ( array( 'p', 'page_id' ) as $query_var ) {
			$post_id = (int) get_query_var( $query_var );
			if ( $post_id > 0 ) {
				$post = get_post( $post_id );
				if ( $post instanceof \WP_Post ) {
					return $post;
				}
			}
		}

		$pagename = get_query_var( 'pagename' );
		if ( is_string( $pagename ) && '' !== $pagename ) {
			$post = get_page_by_path( $pagename, OBJECT, $this->private_content_post_types() );
			if ( $post instanceof \WP_Post ) {
				return $post;
			}
		}

		$name = get_query_var( 'name' );
		if ( is_string( $name ) && '' !== $name ) {
			$posts = get_posts(
				array(
					'name'             => sanitize_title( $name ),
					'post_type'        => $this->private_content_post_types(),
					'post_status'      => array( 'private' ),
					'posts_per_page'   => 1,
					'no_found_rows'    => true,
					'suppress_filters' => true,
				)
			);

			if ( ! empty( $posts[0] ) && $posts[0] instanceof \WP_Post ) {
				return $posts[0];
			}
		}

		foreach ( $this->request_path_candidates() as $path_candidate ) {
			$post = get_page_by_path( $path_candidate, OBJECT, $this->private_content_post_types() );
			if ( $post instanceof \WP_Post ) {
				return $post;
			}
		}

		$post_id = url_to_postid( $this->current_request_url() );
		if ( $post_id > 0 ) {
			$post = get_post( $post_id );
			if ( $post instanceof \WP_Post ) {
				return $post;
			}
		}

		return null;
	}

	/**
	 * @return array<int, string>
	 */
	private function private_content_post_types(): array {
		$post_types = array_merge(
			get_post_types( array( 'public' => true ), 'names' ),
			get_post_types( array( 'publicly_queryable' => true ), 'names' )
		);

		return array_values( array_unique( $post_types ) );
	}

	/**
	 * @return array<int, string>
	 */
	private function request_path_candidates(): array {
		$path = wp_parse_url( $this->current_request_url(), PHP_URL_PATH );
		if ( ! is_string( $path ) || '' === $path ) {
			return array();
		}

		$home_path = wp_parse_url( home_url( '/' ), PHP_URL_PATH );
		if ( is_string( $home_path ) && '/' !== $home_path && str_starts_with( $path, $home_path ) ) {
			$path = substr( $path, strlen( $home_path ) - 1 );
		}

		$path = trim( rawurldecode( $path ), '/' );
		if ( '' === $path ) {
			return array();
		}

		$parts = array_values( array_filter( explode( '/', $path ) ) );

		return array_values(
			array_unique(
				array_filter(
					array(
						$path,
						end( $parts ),
					)
				)
			)
		);
	}

	private function current_request_url(): string {
		$scheme = is_ssl() ? 'https' : 'http';
		$host   = isset( $_SERVER['HTTP_HOST'] ) ? wp_unslash( (string) $_SERVER['HTTP_HOST'] ) : wp_parse_url( home_url(), PHP_URL_HOST );
		$path   = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( (string) $_SERVER['REQUEST_URI'] ) : '/';

		return esc_url_raw( $scheme . '://' . $host . $path );
	}
}
