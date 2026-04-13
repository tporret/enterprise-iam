<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class IdpView {

	/**
	 * @param array<string, mixed> $idp
	 * @param array<string, mixed> $extra
	 * @return array<string, mixed>
	 */
	public static function summary( array $idp, array $extra = array() ): array {
		return array_merge(
			array(
				'id'             => sanitize_text_field( (string) ( $idp['id'] ?? '' ) ),
				'provider_name'  => sanitize_text_field( (string) ( $idp['provider_name'] ?? '' ) ),
				'provider_family' => sanitize_key( (string) ( $idp['provider_family'] ?? '' ) ),
				'protocol'       => sanitize_key( (string) ( $idp['protocol'] ?? '' ) ),
				'domain_mapping' => array_values( array_map( 'sanitize_text_field', (array) ( $idp['domain_mapping'] ?? array() ) ) ),
				'enabled'        => ! empty( $idp['enabled'] ),
			),
			$extra
		);
	}

	/**
	 * @param array<string, mixed> $idp
	 * @param array<string, mixed> $extra
	 * @return array<string, mixed>
	 */
	public static function detail( array $idp, array $extra = array() ): array {
		return array_merge(
			array(
				'id'                         => sanitize_text_field( (string) ( $idp['id'] ?? '' ) ),
				'provider_name'              => sanitize_text_field( (string) ( $idp['provider_name'] ?? '' ) ),
				'provider_family'            => sanitize_key( (string) ( $idp['provider_family'] ?? '' ) ),
				'protocol'                   => sanitize_key( (string) ( $idp['protocol'] ?? '' ) ),
				'client_id'                  => sanitize_text_field( (string) ( $idp['client_id'] ?? '' ) ),
				'client_secret'              => ! empty( $idp['client_secret'] ) ? '••••••••' : '',
				'issuer'                     => esc_url_raw( (string) ( $idp['issuer'] ?? '' ) ),
				'entity_id'                  => sanitize_text_field( (string) ( $idp['entity_id'] ?? '' ) ),
				'certificate'                => sanitize_textarea_field( (string) ( $idp['certificate'] ?? '' ) ),
				'authorization_endpoint'     => esc_url_raw( (string) ( $idp['authorization_endpoint'] ?? '' ) ),
				'token_endpoint'             => esc_url_raw( (string) ( $idp['token_endpoint'] ?? '' ) ),
				'userinfo_endpoint'          => esc_url_raw( (string) ( $idp['userinfo_endpoint'] ?? '' ) ),
				'jwks_uri'                   => esc_url_raw( (string) ( $idp['jwks_uri'] ?? '' ) ),
				'sso_url'                    => esc_url_raw( (string) ( $idp['sso_url'] ?? '' ) ),
				'domain_mapping'             => array_values( array_map( 'sanitize_text_field', (array) ( $idp['domain_mapping'] ?? array() ) ) ),
				'role_mapping'               => (array) ( $idp['role_mapping'] ?? array() ),
				'super_tenant'               => ! empty( $idp['super_tenant'] ),
				'enabled'                    => ! empty( $idp['enabled'] ),
				'override_attribute_mapping' => ! empty( $idp['override_attribute_mapping'] ),
				'custom_email_attr'          => sanitize_text_field( (string) ( $idp['custom_email_attr'] ?? '' ) ),
				'custom_first_name_attr'     => sanitize_text_field( (string) ( $idp['custom_first_name_attr'] ?? '' ) ),
				'custom_last_name_attr'      => sanitize_text_field( (string) ( $idp['custom_last_name_attr'] ?? '' ) ),
				'force_reauth'               => ! empty( $idp['force_reauth'] ),
				'end_session_endpoint'       => esc_url_raw( (string) ( $idp['end_session_endpoint'] ?? '' ) ),
				'slo_url'                    => esc_url_raw( (string) ( $idp['slo_url'] ?? '' ) ),
			),
			$extra
		);
	}
}