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
			$post = get_page_by_path( $pagename, OBJECT, array( 'page', 'post' ) );
			if ( $post instanceof \WP_Post ) {
				return $post;
			}
		}

		$name = get_query_var( 'name' );
		if ( is_string( $name ) && '' !== $name ) {
			$posts = get_posts(
				array(
					'name' => sanitize_title( $name ),
					'post_type' => array( 'post', 'page' ),
					'post_status' => array( 'private' ),
					'posts_per_page' => 1,
					'no_found_rows' => true,
					'suppress_filters' => true,
				)
			);

			if ( ! empty( $posts[0] ) && $posts[0] instanceof \WP_Post ) {
				return $posts[0];
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

	private function current_request_url(): string {
		$scheme = is_ssl() ? 'https' : 'http';
		$host   = isset( $_SERVER['HTTP_HOST'] ) ? wp_unslash( (string) $_SERVER['HTTP_HOST'] ) : wp_parse_url( home_url(), PHP_URL_HOST );
		$path   = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( (string) $_SERVER['REQUEST_URI'] ) : '/';

		return esc_url_raw( $scheme . '://' . $host . $path );
	}
}