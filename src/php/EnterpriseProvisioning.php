<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Just-In-Time (JIT) provisioning for SSO-authenticated users.
 *
 * Given validated identity attributes (SAML or OIDC), this class finds or
 * creates a WordPress user, maps IdP roles, and logs them in.
 *
 * Security controls:
 *  1. Break-glass admin isolation — admin accounts are never managed via SSO.
 *  2. Strict account binding — uses the IdP's immutable UID (OIDC sub / SAML NameID)
 *     as the primary key after first login, not email.
 *  3. JIT role ceiling — caps the maximum role SSO can assign.
 */
final class EnterpriseProvisioning {

	/**
	 * Capabilities that must never be granted through standard tenant SSO.
	 */
	private const BLOCKED_ROLE_CAPABILITIES = array(
		'manage_options',
		'switch_themes',
		'manage_network',
	);

	/**
	 * Ordered role hierarchy from highest to lowest privilege.
	 * Used to enforce the role ceiling.
	 */
	private const ROLE_HIERARCHY = array(
		'administrator' => 5,
		'editor'        => 4,
		'author'        => 3,
		'contributor'   => 2,
		'subscriber'    => 1,
	);

	/**
	 * Provision the user and log them in.
	 *
	 * @param array $idp        IdP config from IdpManager.
	 * @param array $attributes Parsed identity attributes (email, first_name, last_name, groups, idp_uid).
	 * @return true|\WP_Error
	 */
	public static function provision_and_login( array $idp, array $attributes ) {
		$email          = sanitize_email( $attributes['email'] ?? '' );
		$idp_uid        = sanitize_text_field( $attributes['idp_uid'] ?? '' );
		$idp_id         = $idp['id'] ?? '';
		$idp_issuer     = sanitize_text_field( $attributes['idp_issuer'] ?? '' );
		$email_verified = ! empty( $attributes['email_verified'] );

		if ( ! is_email( $email ) ) {
			return new \WP_Error( 'enterprise_provision', 'No valid email address in identity assertion.' );
		}

		// ── 1. Primary lookup: immutable IdP UID ────────────────────────
		$user = self::find_user_by_idp_uid( $idp_id, $idp_uid );

		if ( $user ) {
			// ── Break-glass: reject SSO for administrators / user ID 1 ──
			$admin_check = self::reject_if_admin( $user );
			if ( is_wp_error( $admin_check ) ) {
				return $admin_check;
			}

			// Verify the issuer hasn't changed (iss+sub composite check).
			if ( '' !== $idp_issuer ) {
				$stored_issuer = get_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::IDP_ISSUER ), true );
				if ( '' === $stored_issuer ) {
					// Back-fill issuer for accounts created before this check.
					update_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::IDP_ISSUER ), $idp_issuer );
				} elseif ( $stored_issuer !== $idp_issuer ) {
					return new \WP_Error(
						'enterprise_provision',
						'Issuer mismatch: the identity provider issuer does not match the bound account. Login blocked.'
					);
				}
			}
		} elseif ( '' !== $idp_uid ) {
			// ── 2. First-time binding: fall back to email lookup ─────────
			// Require a verified email before binding an IdP identity to an
			// existing WordPress account. Without this check, an attacker who
			// controls an IdP could claim any email address and hijack the
			// linked WordPress account.
			if ( ! $email_verified ) {
				return new \WP_Error(
					'enterprise_provision',
					'Your identity provider did not confirm your email address (email_verified). Login blocked for account safety.'
				);
			}

			$user = get_user_by( 'email', $email );

			// Multisite: user exists globally but isn't on this site — treat as new.
			if ( is_multisite() && $user && ! is_user_member_of_blog( $user->ID, get_current_blog_id() ) ) {
				$user = null;
			}

			if ( $user ) {
				// Break-glass: reject SSO for administrators / user ID 1.
				$admin_check = self::reject_if_admin( $user );
				if ( is_wp_error( $admin_check ) ) {
					return $admin_check;
				}

				$existing_provider = get_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ), true );

				if ( empty( $existing_provider ) ) {
					return new \WP_Error(
						'enterprise_provision',
						'A local account already exists with this email address. SSO login is not permitted for local accounts.'
					);
				}

				if ( $existing_provider !== $idp_id ) {
					return new \WP_Error(
						'enterprise_provision',
						'This account is managed by a different identity provider.'
					);
				}

				// The user exists and belongs to this IdP but has no UID stored yet.
				// Bind the immutable UID and issuer now.
				$stored_uid = get_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::IDP_UID ), true );
				if ( '' === $stored_uid ) {
					self::clean_sweep_legacy_access( $user->ID );
					self::bind_user_to_idp( $user->ID, $idp_id, $idp_uid, $idp_issuer );
				} elseif ( $stored_uid !== $idp_uid ) {
					// UID mismatch — possible IdP spoofing.
					return new \WP_Error(
						'enterprise_provision',
						'Identity mismatch: the IdP unique identifier does not match the bound account. Login blocked.'
					);
				}
			}
		} else {
			// No idp_uid provided — legacy email-only lookup.
			// Without an immutable UID, email is the only identifier.
			// Require verified email for this unsafe path.
			if ( ! $email_verified ) {
				return new \WP_Error(
					'enterprise_provision',
					'Your identity provider did not confirm your email address (email_verified). Login blocked for account safety.'
				);
			}

			$user = get_user_by( 'email', $email );

			// Multisite: user exists globally but isn't on this site — treat as new.
			if ( is_multisite() && $user && ! is_user_member_of_blog( $user->ID, get_current_blog_id() ) ) {
				$user = null;
			}

			if ( $user ) {
				$admin_check = self::reject_if_admin( $user );
				if ( is_wp_error( $admin_check ) ) {
					return $admin_check;
				}

				$existing_provider = get_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ), true );

				if ( empty( $existing_provider ) ) {
					return new \WP_Error(
						'enterprise_provision',
						'A local account already exists with this email address. SSO login is not permitted for local accounts.'
					);
				}

				if ( $existing_provider !== $idp_id ) {
					return new \WP_Error(
						'enterprise_provision',
						'This account is managed by a different identity provider.'
					);
				}
			}
		}

		// ── 3. New user creation ────────────────────────────────────────
		if ( ! $user ) {
			// Never create a WordPress account from an unverified email.
			if ( ! $email_verified ) {
				return new \WP_Error(
					'enterprise_provision',
					'Cannot create an account: the identity provider did not confirm your email address (email_verified).'
				);
			}

			// ── TOCTOU guard: use a DB-level lock to prevent duplicate
			// accounts when two identical SSO assertions arrive at the
			// same millisecond for a first-time user. The lock serialises
			// the check-email + insert-user window per email address.
			global $wpdb;
			$lock_key = 'ea_jit_' . md5( $email );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$locked = $wpdb->query(
				$wpdb->prepare( "SELECT GET_LOCK(%s, 5)", $lock_key )
			);

			// Re-check after acquiring the lock — the other thread may
			// have already created the user while we waited.
			$user = get_user_by( 'email', $email );

			// Determine if the user is actually on this blog (Multisite).
			$on_this_blog = $user && ( ! is_multisite() || is_user_member_of_blog( $user->ID, get_current_blog_id() ) );

			if ( $user && $on_this_blog ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$wpdb->query( $wpdb->prepare( "SELECT RELEASE_LOCK(%s)", $lock_key ) );

				// The parallel thread created the account; verify it is
				// SSO-managed and belongs to this IdP before proceeding.
				$admin_check = self::reject_if_admin( $user );
				if ( is_wp_error( $admin_check ) ) {
					return $admin_check;
				}
				$existing_provider = get_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ), true );
				if ( ! empty( $existing_provider ) && $existing_provider !== $idp_id ) {
					return new \WP_Error(
						'enterprise_provision',
						'This account is managed by a different identity provider.'
					);
				}
			} elseif ( $user && ! $on_this_blog ) {
				// Multisite: user exists globally but not on this blog.
				// Add them instead of creating a duplicate account.
				$admin_check = self::reject_if_admin( $user );
				if ( is_wp_error( $admin_check ) ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery
					$wpdb->query( $wpdb->prepare( "SELECT RELEASE_LOCK(%s)", $lock_key ) );
					return $admin_check;
				}
				add_user_to_blog( get_current_blog_id(), $user->ID, 'subscriber' );

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$wpdb->query( $wpdb->prepare( "SELECT RELEASE_LOCK(%s)", $lock_key ) );

				// Bind site-scoped SSO identity meta for this blog.
				$should_clean_sweep = self::should_clean_sweep_before_binding( $user->ID );
				self::bind_user_to_idp( $user->ID, $idp_id, $idp_uid, $idp_issuer );
				if ( $should_clean_sweep ) {
					self::clean_sweep_legacy_access( $user->ID );
				}
			} else {
				$username   = self::generate_username( $email );
				$password   = wp_generate_password( 32, true, true );
				$first_name = sanitize_text_field( $attributes['first_name'] ?? '' );
				$last_name  = sanitize_text_field( $attributes['last_name'] ?? '' );
				$display    = trim( "$first_name $last_name" );
				if ( '' === $display ) {
					$display = $username;
				}

				$user_id = wp_insert_user(
					array(
						'user_login'   => $username,
						'user_email'   => $email,
						'user_pass'    => $password,
						'first_name'   => $first_name,
						'last_name'    => $last_name,
						'display_name' => $display,
						'role'         => 'subscriber',
					)
				);

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$wpdb->query( $wpdb->prepare( "SELECT RELEASE_LOCK(%s)", $lock_key ) );

				if ( is_wp_error( $user_id ) ) {
					return $user_id;
				}

				$user = get_user_by( 'id', $user_id );
				self::bind_user_to_idp( $user_id, $idp_id, $idp_uid, $idp_issuer );
			}
		}

		// Map IdP groups → WP roles (only for SSO-provisioned users).
		self::apply_role_mapping( $user, $idp, (array) ( $attributes['groups'] ?? array() ) );

		// ── Session control ─────────────────────────────────────────────
		// Record the SSO login timestamp for session timeout enforcement.
		update_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SSO_LOGIN_AT ), time() );

		// If the IdP provided a session expiry (SAML SessionNotOnOrAfter),
		// store it so the session-check hook can honour it.
		$session_expires = $attributes['session_not_on_or_after'] ?? 0;
		if ( $session_expires > 0 ) {
			update_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::SESSION_EXPIRES ), (int) $session_expires );
		}

		$oidc_id_token = isset( $attributes['oidc_id_token'] ) && is_string( $attributes['oidc_id_token'] )
			? $attributes['oidc_id_token']
			: '';

		if ( 'oidc' === ( $idp['protocol'] ?? '' ) && '' !== $oidc_id_token ) {
			try {
				update_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::OIDC_ID_TOKEN ), Encryption::encrypt( $oidc_id_token ) );
			} catch ( \RuntimeException $e ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Enterprise IAM – Failed to persist OIDC logout token hint: ' . $e->getMessage() );
				delete_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::OIDC_ID_TOKEN ) );
			}
		} else {
			delete_user_meta( $user->ID, SiteMetaKeys::key( SiteMetaKeys::OIDC_ID_TOKEN ) );
		}

		// Use a browser-session cookie (not persistent "remember me") so
		// closing the browser ends the session. The `auth_cookie_expiration`
		// filter in Core.php further caps the server-side lifetime.
		wp_set_auth_cookie( $user->ID, false );
		do_action( 'wp_login', $user->user_login, $user );

		// Store the last-used IdP ID in a long-lived cookie so session-expiry
		// re-auth can redirect seamlessly to the correct provider.
		$idp_id = $idp['id'] ?? '';
		if ( '' !== $idp_id && ! headers_sent() ) {
			setcookie(
				self::last_idp_cookie_name(),
				$idp_id,
				array(
					'expires'  => time() + ( 90 * DAY_IN_SECONDS ),
					'path'     => COOKIEPATH,
					'secure'   => is_ssl(),
					'httponly'  => true,
					'samesite' => 'Lax',
				)
			);
		}

		self::emit_identity_event(
			'sso_login',
			array(
				'user_id'      => $user->ID,
				'idp_id'       => $idp_id,
				'idp_protocol' => $idp['protocol'] ?? '',
				'idp_issuer'   => $idp_issuer,
			)
		);

		return true;
	}

	/**
	 * Break-glass admin isolation.
	 *
	 * User ID 1 and any user with the Administrator role must never be
	 * managed via SSO. If the IdP goes down or is compromised, the local
	 * admin can still log in with a password or passkey.
	 *
	 * @return true|\WP_Error
	 */
	private static function reject_if_admin( \WP_User $user ) {
		if ( 1 === $user->ID || in_array( 'administrator', (array) $user->roles, true ) ) {
			return new \WP_Error(
				'enterprise_provision',
				'Administrator accounts cannot be managed via SSO. Please log in with your local password or passkey.'
			);
		}
		return true;
	}

	/**
	 * Look up a WordPress user by the immutable IdP unique identifier.
	 *
	 * @return \WP_User|null
	 */
	private static function find_user_by_idp_uid( string $idp_id, string $idp_uid ): ?\WP_User {
		if ( '' === $idp_uid || '' === $idp_id ) {
			return null;
		}

		$users = get_users(
			array(
				'meta_query' => array(
					'relation' => 'AND',
					array(
						'key'   => SiteMetaKeys::key( SiteMetaKeys::IDP_UID ),
						'value' => $idp_uid,
					),
					array(
						'key'   => SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ),
						'value' => $idp_id,
					),
				),
				'number'     => 1,
				'fields'     => 'all',
			)
		);

		return ! empty( $users ) ? $users[0] : null;
	}

	/**
	 * Map IdP group claims to a WordPress role.
	 *
	 * Priority: exact group match → wildcard "*" mapping → no change.
	 * The resolved role is capped at the configured role ceiling to prevent
	 * privilege escalation via rogue IdP payloads.
	 */
	private static function apply_role_mapping( \WP_User $user, array $idp, array $groups ): void {
		$mapping = self::decorate_role_mapping(
			(array) ( $idp['role_mapping'] ?? array() ),
			self::is_super_tenant_idp( $idp )
		);

		if ( empty( $mapping ) ) {
			return;
		}

		$role_definition = self::resolve_role_definition_from_groups( $mapping, $groups );

		if ( null === $role_definition ) {
			return;
		}

		$resolved_role = self::cap_role( $role_definition['role'], (bool) $role_definition['super_tenant'] );
		if ( null === $resolved_role ) {
			return;
		}

		$user->set_role( $resolved_role );
	}

	/**
	 * Public entry point for SCIM group-based role assignment.
	 *
	 * Aggregates role mappings from all configured IdPs and resolves the
	 * given group names to a WordPress role, respecting the role ceiling.
	 *
	 * @param \WP_User $user   The WordPress user to update.
	 * @param string[] $groups One or more IdP group displayNames.
	 */
	public static function assign_role( \WP_User $user, array $groups ): void {
		// Aggregate role mappings across all configured IdPs.
		$mapping = array();
		foreach ( IdpManager::all() as $idp ) {
			foreach ( self::decorate_role_mapping( (array) ( $idp['role_mapping'] ?? array() ), self::is_super_tenant_idp( $idp ) ) as $group => $definition ) {
				$mapping[ $group ] = $definition;
			}
		}

		if ( empty( $mapping ) ) {
			return;
		}

		$role_definition = self::resolve_role_definition_from_groups( $mapping, $groups );

		if ( null === $role_definition ) {
			return;
		}

		$resolved_role = self::cap_role( $role_definition['role'], (bool) $role_definition['super_tenant'] );
		if ( null === $resolved_role ) {
			return;
		}

		$user->set_role( $resolved_role );
	}

	/**
	 * Decorate a role mapping table with the IdP's privilege context.
	 *
	 * @param array<string,string> $mapping
	 * @return array<string, array{role: string, super_tenant: bool}>
	 */
	private static function decorate_role_mapping( array $mapping, bool $super_tenant ): array {
		$decorated = array();

		foreach ( $mapping as $group => $role ) {
			$decorated[ (string) $group ] = array(
				'role'         => sanitize_text_field( (string) $role ),
				'super_tenant' => $super_tenant,
			);
		}

		return $decorated;
	}

	/**
	 * Resolve a WordPress role definition from group names using a mapping table.
	 *
	 * @param array<string, array{role: string, super_tenant: bool}> $mapping
	 * @param string[]                                               $groups
	 * @return array{role: string, super_tenant: bool}|null
	 */
	private static function resolve_role_definition_from_groups( array $mapping, array $groups ): ?array {
		$resolved_role = null;

		foreach ( $groups as $group ) {
			$group_lower = strtolower( (string) $group );
			foreach ( $mapping as $idp_group => $definition ) {
				if ( strtolower( $idp_group ) === $group_lower ) {
					$resolved_role = $definition;
					break 2;
				}
			}
		}

		// No group matched — use the wildcard "*" mapping if configured.
		if ( null === $resolved_role && isset( $mapping['*'] ) ) {
			$resolved_role = $mapping['*'];
		}

		return $resolved_role;
	}

	/**
	 * Cap a role at the configured role ceiling.
	 *
	 * If the requested role is more privileged than the ceiling, return the
	 * ceiling role instead. Unknown or blocked roles are rejected.
	 */
	private static function cap_role( string $role, bool $super_tenant = false ): ?string {
		$role_object = get_role( $role );
		if ( null === $role_object ) {
			return null;
		}

		if ( self::role_has_blocked_capabilities( $role_object->capabilities ) ) {
			return $super_tenant ? $role : null;
		}

		$settings = SettingsController::read();
		$ceiling  = $settings['role_ceiling'] ?? 'editor';

		$role_level    = self::ROLE_HIERARCHY[ $role ] ?? 0;
		$ceiling_level = self::ROLE_HIERARCHY[ $ceiling ] ?? self::ROLE_HIERARCHY['editor'];

		if ( $role_level > $ceiling_level ) {
			return $ceiling;
		}

		return $role;
	}

	/**
	 * Check whether a target role exposes privileged administrative capabilities.
	 *
	 * @param array<string, bool> $capabilities
	 */
	private static function role_has_blocked_capabilities( array $capabilities ): bool {
		foreach ( self::BLOCKED_ROLE_CAPABILITIES as $capability ) {
			if ( ! empty( $capabilities[ $capability ] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Determine whether the IdP is allowed to grant privileged roles.
	 */
	private static function is_super_tenant_idp( array $idp ): bool {
		return ! empty( $idp['super_tenant'] );
	}

	/**
	 * Derive a unique username from an email address.
	 */
	private static function generate_username( string $email ): string {
		$base = sanitize_user( strtok( $email, '@' ), true );

		if ( ! username_exists( $base ) ) {
			return $base;
		}

		$i = 2;
		while ( username_exists( $base . $i ) ) {
			++$i;
		}

		return $base . $i;
	}

	/**
	 * Per-blog cookie name used for seamless SSO re-authentication.
	 */
	private static function last_idp_cookie_name(): string {
		if ( ! is_multisite() ) {
			return 'enterprise_auth_last_idp';
		}

		return 'enterprise_auth_last_idp_' . get_current_blog_id();
	}

	/**
	 * Bind a user to an IdP on the current site.
	 */
	private static function bind_user_to_idp( int $user_id, string $idp_id, string $idp_uid, string $idp_issuer ): void {
		update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::SSO_PROVIDER ), $idp_id );

		if ( '' !== $idp_uid ) {
			update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::IDP_UID ), $idp_uid );
		}

		if ( '' !== $idp_issuer ) {
			update_user_meta( $user_id, SiteMetaKeys::key( SiteMetaKeys::IDP_ISSUER ), $idp_issuer );
		}
	}

	/**
	 * Whether the user is being bound to any identity system for the first time.
	 */
	private static function should_clean_sweep_before_binding( int $user_id ): bool {
		$all_meta = get_user_meta( $user_id );
		if ( ! is_array( $all_meta ) ) {
			return true;
		}

		foreach ( $all_meta as $meta_key => $values ) {
			if ( ! self::is_identity_binding_meta_key( (string) $meta_key ) ) {
				continue;
			}

			foreach ( (array) $values as $value ) {
				if ( '' !== (string) $value ) {
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Check whether a usermeta key represents an identity binding.
	 */
	private static function is_identity_binding_meta_key( string $meta_key ): bool {
		if ( in_array( $meta_key, array( SiteMetaKeys::SSO_PROVIDER, SiteMetaKeys::IDP_UID, SiteMetaKeys::SCIM_ID ), true ) ) {
			return true;
		}

		return 1 === preg_match( '/^_ea_\d+_(?:sso_provider|idp_uid|scim_id)$/', $meta_key );
	}

	/**
	 * Remove legacy local access when an existing account becomes IdP-managed.
	 */
	private static function clean_sweep_legacy_access( int $user_id ): void {
		wp_set_password( wp_generate_password( 64, true, true ), $user_id );

		if ( class_exists( '\WP_Application_Passwords' ) && method_exists( '\WP_Application_Passwords', 'delete_all_application_passwords' ) ) {
			\WP_Application_Passwords::delete_all_application_passwords( $user_id );
		}

		delete_user_meta( $user_id, '_application_passwords' );

		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->usermeta} WHERE user_id = %d AND (meta_key LIKE %s OR meta_key LIKE %s)",
				$user_id,
				'%app_password%',
				'%application_password%'
			)
		);

		\WP_Session_Tokens::get_instance( $user_id )->destroy_all();
	}

	/**
	 * Emit an auditable identity event.
	 *
	 * @param array<string, mixed> $context
	 */
	private static function emit_identity_event( string $event, array $context = array() ): void {
		do_action(
			'ea_identity_event',
			$event,
			array_merge(
				array(
					'blog_id' => get_current_blog_id(),
				),
				$context
			)
		);
	}
}
