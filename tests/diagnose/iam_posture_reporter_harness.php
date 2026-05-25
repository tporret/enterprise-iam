<?php

declare( strict_types=1 );

define( 'ABSPATH', __DIR__ . '/../../' );

require_once __DIR__ . '/../../src/php/IamPostureReporter.php';

$assert = static function ( bool $condition, string $message ): void {
	if ( ! $condition ) {
		fwrite( STDERR, "FAIL: {$message}\n" );
		exit( 1 );
	}
};

$reflection = new ReflectionClass( EnterpriseAuth\Plugin\IamPostureReporter::class );
$reporter   = $reflection->newInstanceWithoutConstructor();

$summarize = $reflection->getMethod( 'summarize_inspections' );
$summarize->setAccessible( true );
$findings = $reflection->getMethod( 'findings' );
$findings->setAccessible( true );
$score = $reflection->getMethod( 'score' );
$score->setAccessible( true );

$summary = $summarize->invoke(
	$reporter,
	array(
		7 => array(
			'identity_source' => 'sso',
			'suspended_site' => false,
			'suspended_network' => false,
			'passkeys' => array(
				'total' => 1,
				'compliant' => 1,
				'legacy_non_compliant' => 0,
				'last_used_at' => 100,
				'step_up_required' => false,
			),
		),
		9 => array(
			'identity_source' => 'local',
			'suspended_site' => true,
			'suspended_network' => false,
			'passkeys' => array(
				'total' => 0,
				'compliant' => 0,
				'legacy_non_compliant' => 0,
				'last_used_at' => 0,
				'step_up_required' => true,
			),
		),
		11 => array(
			'identity_source' => 'mixed',
			'suspended_site' => false,
			'suspended_network' => false,
			'passkeys' => array(
				'total' => 2,
				'compliant' => 1,
				'legacy_non_compliant' => 1,
				'last_used_at' => 200,
				'step_up_required' => true,
			),
		),
	)
);

$assert( 3 === $summary['users']['total'], 'Summary should count users.' );
$assert( 1 === $summary['users']['suspended'], 'Summary should count suspended users.' );
$assert( 1 === $summary['identity_sources']['sso'], 'Summary should count SSO users.' );
$assert( 1 === $summary['identity_sources']['local'], 'Summary should count local users.' );
$assert( 1 === $summary['identity_sources']['mixed'], 'Summary should count mixed users.' );
$assert( 3 === $summary['passkeys']['total'], 'Summary should aggregate passkeys.' );
$assert( 1 === $summary['passkeys']['legacy_non_compliant'], 'Summary should aggregate legacy passkeys.' );
$assert( 2 === $summary['passkeys']['users_requiring_step_up'], 'Summary should count step-up users.' );
$assert( 200 === $summary['passkeys']['latest_last_used_at'], 'Summary should keep latest passkey use.' );

$posture_findings = $findings->invoke(
	$reporter,
	$summary,
	array(
		'app_passwords' => true,
		'private_content_login_required' => false,
	),
	0
);
$finding_codes = array_column( $posture_findings, 'code' );

foreach ( array( 'no_identity_provider', 'local_accounts_present', 'users_without_passkeys', 'legacy_passkeys', 'step_up_required', 'application_passwords_enabled', 'private_content_gate_disabled' ) as $code ) {
	$assert( in_array( $code, $finding_codes, true ), "Expected finding {$code}." );
}

$assert( 10 === $score->invoke( $reporter, $posture_findings ), 'Score should subtract finding weights from 100.' );

$clean_findings = $findings->invoke(
	$reporter,
	$summarize->invoke(
		$reporter,
		array(
			1 => array(
				'identity_source' => 'sso',
				'passkeys' => array(
					'total' => 1,
					'compliant' => 1,
					'legacy_non_compliant' => 0,
					'step_up_required' => false,
				),
			),
		)
	),
	array(
		'app_passwords' => false,
		'private_content_login_required' => true,
	),
	1
);
$assert( array() === $clean_findings, 'Healthy posture should have no findings.' );
$assert( 100 === $score->invoke( $reporter, $clean_findings ), 'Healthy posture should score 100.' );

echo "PASS: IAM posture reporter summarizes and scores posture signals.\n";
