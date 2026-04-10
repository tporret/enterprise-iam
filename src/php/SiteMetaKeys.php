<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Centralised user-meta key registry with Multisite tenant isolation.
 *
 * In a single-site installation every key is returned unchanged for
 * backward compatibility.  In WordPress Multisite the key is prefixed
 * with the current Blog ID so that each sub-site's SSO / SCIM
 * identity data is fully isolated within the shared wp_usermeta table.
 *
 * Example (Blog ID 3):
 *   _enterprise_auth_idp_uid  →  _ea_3_idp_uid
 */
final class SiteMetaKeys {

	// ── Identity meta keys ──────────────────────────────────────────────
	public const SSO_PROVIDER    = '_enterprise_auth_sso_provider';
	public const IDP_UID         = '_enterprise_auth_idp_uid';
	public const IDP_ISSUER      = '_enterprise_auth_idp_issuer';

	// ── Session meta keys ───────────────────────────────────────────────
	public const SSO_LOGIN_AT    = '_enterprise_auth_sso_login_at';
	public const SESSION_EXPIRES = '_enterprise_auth_session_expires';

	// ── SCIM meta keys ──────────────────────────────────────────────────
	public const SCIM_ID         = 'enterprise_iam_scim_id';
	public const SCIM_SUSPENDED  = 'is_scim_suspended';

	/**
	 * Mapping from base keys to short suffixes used in the Multisite
	 * prefixed format: _ea_{blog_id}_{suffix}.
	 *
	 * @var array<string, string>
	 */
	private const SHORT_MAP = array(
		self::SSO_PROVIDER    => 'sso_provider',
		self::IDP_UID         => 'idp_uid',
		self::IDP_ISSUER      => 'idp_issuer',
		self::SSO_LOGIN_AT    => 'sso_login_at',
		self::SESSION_EXPIRES => 'session_expires',
		self::SCIM_ID         => 'scim_id',
		self::SCIM_SUSPENDED  => 'scim_suspended',
	);

	/**
	 * Return a site-scoped meta key for the current blog.
	 *
	 * Single-site: returns the base key unchanged (backward compatible).
	 * Multisite:   returns '_ea_{blog_id}_{suffix}' for tenant isolation.
	 *
	 * @param string $base_key One of this class's constants.
	 */
	public static function key( string $base_key ): string {
		if ( ! is_multisite() ) {
			return $base_key;
		}

		$suffix = self::SHORT_MAP[ $base_key ] ?? $base_key;
		return '_ea_' . get_current_blog_id() . '_' . $suffix;
	}
}
