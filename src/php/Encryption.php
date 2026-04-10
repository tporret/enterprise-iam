<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AES-256-GCM encryption for secrets at rest.
 *
 * Derives a 256-bit key from the WordPress AUTH_KEY salt using HKDF.
 * Secrets are stored as `ea_enc:<base64(iv + tag + ciphertext)>` so
 * that legacy plaintext values are migrated transparently on first
 * read-then-write.
 */
final class Encryption {

	private const CIPHER     = 'aes-256-gcm';
	private const PREFIX     = 'ea_enc:';
	private const IV_LENGTH  = 12;
	private const TAG_LENGTH = 16;

	/**
	 * Encrypt a plaintext string.
	 *
	 * Returns the original string unchanged if OpenSSL is unavailable
	 * (graceful degradation — logged as a warning).
	 */
	public static function encrypt( string $plaintext ): string {
		if ( '' === $plaintext ) {
			return '';
		}

		if ( ! function_exists( 'openssl_encrypt' ) ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( 'Enterprise IAM: openssl extension not available — client_secret stored unencrypted.' );
			return $plaintext;
		}

		$key = self::derive_key();
		$iv  = openssl_random_pseudo_bytes( self::IV_LENGTH );
		$tag = '';

		$ciphertext = openssl_encrypt(
			$plaintext,
			self::CIPHER,
			$key,
			OPENSSL_RAW_DATA,
			$iv,
			$tag,
			'',
			self::TAG_LENGTH
		);

		if ( false === $ciphertext ) {
			return $plaintext; // Fallback — don't lose the secret.
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		return self::PREFIX . base64_encode( $iv . $tag . $ciphertext );
	}

	/**
	 * Decrypt a stored value.
	 *
	 * If the value does not carry the `ea_enc:` prefix it is assumed to be
	 * a legacy plaintext value and is returned as-is (transparent migration).
	 */
	public static function decrypt( string $stored ): string {
		if ( '' === $stored ) {
			return '';
		}

		// Legacy plaintext — return unchanged (will be encrypted on next save).
		if ( ! str_starts_with( $stored, self::PREFIX ) ) {
			return $stored;
		}

		if ( ! function_exists( 'openssl_decrypt' ) ) {
			return ''; // Cannot decrypt without openssl.
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$raw = base64_decode( substr( $stored, strlen( self::PREFIX ) ), true );
		if ( false === $raw || strlen( $raw ) < ( self::IV_LENGTH + self::TAG_LENGTH + 1 ) ) {
			return ''; // Corrupted payload.
		}

		$key = self::derive_key();
		$iv  = substr( $raw, 0, self::IV_LENGTH );
		$tag = substr( $raw, self::IV_LENGTH, self::TAG_LENGTH );
		$ct  = substr( $raw, self::IV_LENGTH + self::TAG_LENGTH );

		$plaintext = openssl_decrypt( $ct, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag );

		return ( false !== $plaintext ) ? $plaintext : '';
	}

	/**
	 * Derive a 256-bit encryption key from the site's AUTH_KEY salt.
	 *
	 * Uses HKDF (hash_hkdf) when available (PHP 7.1.2+), otherwise a
	 * simple SHA-256 hash.
	 */
	private static function derive_key(): string {
		$salt = defined( 'AUTH_KEY' ) ? AUTH_KEY : 'enterprise-iam-fallback-key';

		if ( function_exists( 'hash_hkdf' ) ) {
			return hash_hkdf( 'sha256', $salt, 32, 'enterprise-iam-encryption' );
		}

		return hash( 'sha256', $salt, true );
	}
}
