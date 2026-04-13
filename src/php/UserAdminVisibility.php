<?php

declare( strict_types=1 );

namespace EnterpriseAuth\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class UserAdminVisibility {

	private const COLUMN_IDENTITY = 'enterprise_auth_identity';
	private const COLUMN_PROVIDER = 'enterprise_auth_provider';
	private const COLUMN_PASSKEYS = 'enterprise_auth_passkeys';
	private const COLUMN_STATE = 'enterprise_auth_state';

	private UserIdentityInspector $inspector;

	/**
	 * @var array<int, array<string, mixed>>|null
	 */
	private ?array $list_cache = null;

	public function __construct( ?UserIdentityInspector $inspector = null ) {
		$this->inspector = $inspector ?? new UserIdentityInspector();
	}

	public function init(): void {
		add_filter( 'manage_users_columns', array( $this, 'register_columns' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'render_users_column' ), 10, 3 );
		add_action( 'show_user_profile', array( $this, 'render_profile_panel' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_panel' ) );
		add_action( 'admin_head-users.php', array( $this, 'output_styles' ) );
		add_action( 'admin_head-profile.php', array( $this, 'output_styles' ) );
		add_action( 'admin_head-user-edit.php', array( $this, 'output_styles' ) );
	}

	/**
	 * @param array<string, string> $columns
	 * @return array<string, string>
	 */
	public function register_columns( array $columns ): array {
		$columns[ self::COLUMN_IDENTITY ] = __( 'Identity', 'enterprise-auth' );
		$columns[ self::COLUMN_PROVIDER ] = __( 'Provider', 'enterprise-auth' );
		$columns[ self::COLUMN_PASSKEYS ] = __( 'Passkeys', 'enterprise-auth' );
		$columns[ self::COLUMN_STATE ]    = __( 'State', 'enterprise-auth' );

		return $columns;
	}

	public function render_users_column( string $output, string $column_name, int $user_id ): string {
		if ( ! in_array( $column_name, array( self::COLUMN_IDENTITY, self::COLUMN_PROVIDER, self::COLUMN_PASSKEYS, self::COLUMN_STATE ), true ) ) {
			return $output;
		}

		$identity = $this->inspect_for_list( $user_id );

		switch ( $column_name ) {
			case self::COLUMN_IDENTITY:
				return $this->render_badges( array( $this->identity_label( (string) $identity['identity_source'] ) ) );

			case self::COLUMN_PROVIDER:
				$provider = '' !== (string) $identity['provider_name']
					? (string) $identity['provider_name']
					: __( 'Local', 'enterprise-auth' );

				$protocol = strtoupper( (string) $identity['protocol'] );
				$badges   = array( $provider );
				if ( '' !== $protocol ) {
					$badges[] = $protocol;
				}

				return $this->render_badges( $badges );

			case self::COLUMN_PASSKEYS:
				return esc_html( $this->passkey_summary_label( (array) $identity['passkeys'] ) );

			case self::COLUMN_STATE:
				return $this->render_badges( $this->state_labels( $identity ) );
		}

		return $output;
	}

	public function render_profile_panel( \WP_User $user ): void {
		$identity     = $this->inspector->inspect( $user );
		$blog_details = is_multisite() ? get_blog_details( get_current_blog_id() ) : null;
		$context_name = $blog_details && isset( $blog_details->blogname ) ? (string) $blog_details->blogname : get_bloginfo( 'name' );
		$context_url  = home_url( '/' );
		$passkeys     = (array) $identity['passkeys'];
		?>
		<h2><?php echo esc_html__( 'Enterprise Auth', 'enterprise-auth' ); ?></h2>
		<table class="form-table" role="presentation">
			<tbody>
				<?php if ( is_multisite() ) : ?>
					<tr>
						<th><label><?php echo esc_html__( 'Current Site Context', 'enterprise-auth' ); ?></label></th>
						<td>
							<p class="ea-identity-value"><strong><?php echo esc_html( $context_name ); ?></strong></p>
							<p class="description"><?php echo esc_html( $context_url ); ?></p>
						</td>
					</tr>
				<?php endif; ?>
				<tr>
					<th><label><?php echo esc_html__( 'Identity Source', 'enterprise-auth' ); ?></label></th>
					<td><?php echo $this->render_badges( array( $this->identity_label( (string) $identity['identity_source'] ) ) ); ?></td>
				</tr>
				<tr>
					<th><label><?php echo esc_html__( 'Provider', 'enterprise-auth' ); ?></label></th>
					<td>
						<p class="ea-identity-value"><strong><?php echo esc_html( '' !== (string) $identity['provider_name'] ? (string) $identity['provider_name'] : __( 'Local', 'enterprise-auth' ) ); ?></strong></p>
						<?php if ( '' !== (string) $identity['provider_id'] ) : ?>
							<p class="description"><?php echo esc_html( sprintf( 'ID: %s', (string) $identity['provider_id'] ) ); ?></p>
						<?php endif; ?>
						<?php if ( '' !== (string) $identity['protocol'] ) : ?>
							<p class="description"><?php echo esc_html( strtoupper( (string) $identity['protocol'] ) ); ?></p>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<th><label><?php echo esc_html__( 'IdP UID', 'enterprise-auth' ); ?></label></th>
					<td><p class="ea-identity-value"><?php echo esc_html( '' !== (string) $identity['idp_uid_masked'] ? (string) $identity['idp_uid_masked'] : '—' ); ?></p></td>
				</tr>
				<tr>
					<th><label><?php echo esc_html__( 'Issuer', 'enterprise-auth' ); ?></label></th>
					<td><p class="ea-identity-value"><?php echo esc_html( '' !== (string) $identity['issuer'] ? (string) $identity['issuer'] : '—' ); ?></p></td>
				</tr>
				<tr>
					<th><label><?php echo esc_html__( 'SCIM External ID', 'enterprise-auth' ); ?></label></th>
					<td><p class="ea-identity-value"><?php echo esc_html( '' !== (string) $identity['scim_external_id_masked'] ? (string) $identity['scim_external_id_masked'] : '—' ); ?></p></td>
				</tr>
				<tr>
					<th><label><?php echo esc_html__( 'Site Suspension', 'enterprise-auth' ); ?></label></th>
					<td><?php echo $this->render_badges( array( $identity['suspended_site'] ? __( 'Suspended', 'enterprise-auth' ) : __( 'Active', 'enterprise-auth' ) ) ); ?></td>
				</tr>
				<tr>
					<th><label><?php echo esc_html__( 'Network Suspension', 'enterprise-auth' ); ?></label></th>
					<td><?php echo $this->render_badges( array( $identity['suspended_network'] ? __( 'Suspended', 'enterprise-auth' ) : __( 'Active', 'enterprise-auth' ) ) ); ?></td>
				</tr>
				<tr>
					<th><label><?php echo esc_html__( 'Last SSO Login', 'enterprise-auth' ); ?></label></th>
					<td><p class="ea-identity-value"><?php echo esc_html( $this->format_timestamp( (int) $identity['last_sso_login_at'] ) ); ?></p></td>
				</tr>
				<tr>
					<th><label><?php echo esc_html__( 'Session Expires', 'enterprise-auth' ); ?></label></th>
					<td><p class="ea-identity-value"><?php echo esc_html( $this->format_timestamp( (int) $identity['session_expires_at'] ) ); ?></p></td>
				</tr>
				<tr>
					<th><label><?php echo esc_html__( 'Passkey Counts', 'enterprise-auth' ); ?></label></th>
					<td>
						<p class="ea-identity-value"><?php echo esc_html( sprintf( __( '%1$d total / %2$d compliant / %3$d legacy', 'enterprise-auth' ), (int) ( $passkeys['total'] ?? 0 ), (int) ( $passkeys['compliant'] ?? 0 ), (int) ( $passkeys['legacy_non_compliant'] ?? 0 ) ) ); ?></p>
					</td>
				</tr>
				<tr>
					<th><label><?php echo esc_html__( 'Last Passkey Use', 'enterprise-auth' ); ?></label></th>
					<td><p class="ea-identity-value"><?php echo esc_html( $this->format_timestamp( (int) ( $passkeys['last_used_at'] ?? 0 ) ) ); ?></p></td>
				</tr>
				<tr>
					<th><label><?php echo esc_html__( 'Passkey Step-Up Required', 'enterprise-auth' ); ?></label></th>
					<td><?php echo $this->render_badges( array( ! empty( $passkeys['step_up_required'] ) ? __( 'Required', 'enterprise-auth' ) : __( 'Not Required', 'enterprise-auth' ) ) ); ?></td>
				</tr>
			</tbody>
		</table>
		<p class="description"><?php echo esc_html__( 'This panel is read-only. Sensitive identifiers are masked and security bindings remain managed by provisioning, SCIM, and passkey policy flows.', 'enterprise-auth' ); ?></p>
		<?php
	}

	public function output_styles(): void {
		?>
		<style>
			.column-enterprise_auth_identity,
			.column-enterprise_auth_provider,
			.column-enterprise_auth_passkeys,
			.column-enterprise_auth_state {
				width: 12%;
			}

			.ea-identity-badge {
				display: inline-block;
				margin: 0 6px 6px 0;
				padding: 2px 8px;
				border-radius: 999px;
				background: #eef2ff;
				color: #243b53;
				font-size: 12px;
				font-weight: 600;
			}

			.ea-identity-value {
				margin: 0;
			}
		</style>
		<?php
	}

	/**
	 * @return array<string, mixed>
	 */
	private function inspect_for_list( int $user_id ): array {
		if ( null === $this->list_cache ) {
			$this->prime_list_cache();
		}

		if ( isset( $this->list_cache[ $user_id ] ) ) {
			return $this->list_cache[ $user_id ];
		}

		$this->list_cache[ $user_id ] = $this->inspector->inspect( $user_id );

		return $this->list_cache[ $user_id ];
	}

	private function prime_list_cache(): void {
		$this->list_cache = array();

		global $wp_list_table;
		if ( ! isset( $wp_list_table ) || ! is_object( $wp_list_table ) || empty( $wp_list_table->items ) || ! is_array( $wp_list_table->items ) ) {
			return;
		}

		$user_ids = array();
		foreach ( $wp_list_table->items as $item ) {
			if ( $item instanceof \WP_User ) {
				$user_ids[] = $item->ID;
			}
		}

		$this->list_cache = $this->inspector->inspect_many( $user_ids );
	}

	/**
	 * @param array<int, string> $labels
	 */
	private function render_badges( array $labels ): string {
		$labels = array_values( array_filter( array_map( 'strval', $labels ) ) );

		if ( array() === $labels ) {
			return '<span class="ea-identity-badge">—</span>';
		}

		$html = '';
		foreach ( $labels as $label ) {
			$html .= '<span class="ea-identity-badge">' . esc_html( $label ) . '</span>';
		}

		return $html;
	}

	private function identity_label( string $identity_source ): string {
		return match ( $identity_source ) {
			'sso' => __( 'SSO', 'enterprise-auth' ),
			'scim' => __( 'SCIM', 'enterprise-auth' ),
			'mixed' => __( 'SSO + SCIM history', 'enterprise-auth' ),
			default => __( 'Local', 'enterprise-auth' ),
		};
	}

	/**
	 * @param array<string, mixed> $identity
	 * @return array<int, string>
	 */
	private function state_labels( array $identity ): array {
		$labels = array();

		if ( ! empty( $identity['suspended_network'] ) ) {
			$labels[] = __( 'Suspended (Network)', 'enterprise-auth' );
		} elseif ( ! empty( $identity['suspended_site'] ) ) {
			$labels[] = __( 'Suspended (Site)', 'enterprise-auth' );
		}

		if ( ! empty( $identity['passkeys']['step_up_required'] ) ) {
			$labels[] = __( 'Step-Up Required', 'enterprise-auth' );
		}

		if ( array() === $labels ) {
			$labels[] = __( 'Active', 'enterprise-auth' );
		}

		return $labels;
	}

	/**
	 * @param array<string, mixed> $passkeys
	 */
	private function passkey_summary_label( array $passkeys ): string {
		$total      = (int) ( $passkeys['total'] ?? 0 );
		$compliant  = (int) ( $passkeys['compliant'] ?? 0 );
		$legacy     = (int) ( $passkeys['legacy_non_compliant'] ?? 0 );

		if ( $total <= 0 ) {
			return __( 'None', 'enterprise-auth' );
		}

		$parts = array();
		if ( $compliant > 0 ) {
			$parts[] = sprintf( __( '%d compliant', 'enterprise-auth' ), $compliant );
		}

		if ( $legacy > 0 ) {
			$parts[] = sprintf( __( '%d legacy', 'enterprise-auth' ), $legacy );
		}

		if ( array() === $parts ) {
			$parts[] = sprintf( __( '%d total', 'enterprise-auth' ), $total );
		}

		return implode( ' / ', $parts );
	}

	private function format_timestamp( int $timestamp ): string {
		if ( $timestamp <= 0 ) {
			return '—';
		}

		return wp_date( 'Y-m-d H:i:s T', $timestamp );
	}
}