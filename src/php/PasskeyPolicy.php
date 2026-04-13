<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Webauthn\PublicKeyCredentialSource;

/**
 * Tenant-scoped passkey assurance policy and migration helpers.
 */
final class PasskeyPolicy {

	public const COMPLIANCE_STATUS_COMPLIANT = CredentialRepository::COMPLIANCE_STATUS_COMPLIANT;
	public const COMPLIANCE_STATUS_LEGACY_NON_COMPLIANT = CredentialRepository::COMPLIANCE_STATUS_LEGACY_NON_COMPLIANT;
	private const STEP_UP_TRANSIENT_PREFIX = 'ea_stepup_';

	public static function requires_device_bound_authenticators(): bool {
		$settings = SettingsController::read();

		return (bool) ( $settings['require_device_bound_authenticators'] ?? false );
	}

	public static function enforce_device_bound_registration_policy( PublicKeyCredentialSource $credential_source ): void {
		if ( ! self::requires_device_bound_authenticators() ) {
			return;
		}

		if ( true === $credential_source->backupEligible ) {
			throw new \RuntimeException( 'Synced backup-eligible passkeys are not permitted when a tenant requires a device-bound passkey.' );
		}
	}

	public static function compliance_status_for_new_credential( PublicKeyCredentialSource $credential_source ): string {
		if ( self::requires_device_bound_authenticators() && true === $credential_source->backupEligible ) {
			return self::COMPLIANCE_STATUS_LEGACY_NON_COMPLIANT;
		}

		return self::COMPLIANCE_STATUS_COMPLIANT;
	}

	public static function current_registration_origin(): string {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );

		return is_string( $host ) && '' !== $host ? $host : home_url();
	}

	public static function sync_device_bound_policy( bool $previous, bool $current ): void {
		if ( $previous === $current ) {
			return;
		}

		if ( $current ) {
			CredentialRepository::mark_backup_eligible_credentials_legacy_non_compliant();
			return;
		}

		CredentialRepository::restore_legacy_non_compliant_credentials();
		delete_metadata( 'user', 0, SiteMetaKeys::key( SiteMetaKeys::PASSKEY_STEP_UP_REQUIRED ), '', true );
	}

	public static function activate_step_up( int $user_id, string $redirect_to = '' ): void {
		update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::PASSKEY_STEP_UP_REQUIRED ), 1 );
		set_transient( self::step_up_transient_key( $user_id ), self::validated_redirect_target( $redirect_to ), HOUR_IN_SECONDS );
	}

	public static function is_step_up_required_for_user( int $user_id ): bool {
		if ( $user_id <= 0 || ! self::requires_device_bound_authenticators() ) {
			return false;
		}

		return (bool) get_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::PASSKEY_STEP_UP_REQUIRED ), true );
	}

	public static function step_up_url(): string {
		return AdminUI::step_up_url();
	}

	public static function complete_step_up_if_satisfied( int $user_id ): string {
		if ( $user_id <= 0 ) {
			return admin_url();
		}

		if ( ! self::requires_device_bound_authenticators() ) {
			return '';
		}

		if ( ! CredentialRepository::user_has_compliant_credential( $user_id ) ) {
			return self::is_step_up_required_for_user( $user_id ) ? self::step_up_url() : '';
		}

		CredentialRepository::delete_legacy_non_compliant_for_user( $user_id );

		if ( ! self::is_step_up_required_for_user( $user_id ) ) {
			return '';
		}

		delete_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::PASSKEY_STEP_UP_REQUIRED ) );

		$redirect_to = get_transient( self::step_up_transient_key( $user_id ) );
		delete_transient( self::step_up_transient_key( $user_id ) );

		$redirect_to = is_string( $redirect_to ) ? self::validated_redirect_target( $redirect_to ) : '';

		return '' !== $redirect_to ? $redirect_to : admin_url();
	}

	private static function step_up_transient_key( int $user_id ): string {
		$key = self::STEP_UP_TRANSIENT_PREFIX . $user_id;

		if ( ! is_multisite() ) {
			return $key;
		}

		return 'ea_' . get_current_blog_id() . '_' . $key;
	}

	private static function validated_redirect_target( string $redirect_to ): string {
		$redirect_to = trim( $redirect_to );

		if ( '' === $redirect_to ) {
			return '';
		}

		return wp_validate_redirect( $redirect_to, '' );
	}
}