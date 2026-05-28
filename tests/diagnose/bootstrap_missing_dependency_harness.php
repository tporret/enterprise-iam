<?php

declare( strict_types=1 );

$plugin_root = dirname( __DIR__, 2 );
$plugin_file = $plugin_root . '/enterprise-iam.php';
$temp_dir    = sys_get_temp_dir() . '/enterprise-iam-bootstrap-deps-' . getmypid();

register_shutdown_function(
	static function () use ( $temp_dir ): void {
		if ( ! is_dir( $temp_dir ) ) {
			return;
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $temp_dir, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::CHILD_FIRST
		);

		foreach ( $iterator as $item ) {
			$item->isDir() ? rmdir( $item->getPathname() ) : unlink( $item->getPathname() );
		}

		rmdir( $temp_dir );
	}
);

if ( ! mkdir( $temp_dir . '/vendor', 0777, true ) && ! is_dir( $temp_dir . '/vendor' ) ) {
	fwrite( STDERR, "FAIL: Could not create temporary plugin fixture.\n" );
	exit( 1 );
}

copy( $plugin_file, $temp_dir . '/enterprise-iam.php' );

$source_root = var_export( $plugin_root . '/src/php/', true );
file_put_contents(
	$temp_dir . '/vendor/autoload.php',
	"<?php\nspl_autoload_register(static function (string \$class) {\n\t\$prefix = 'EnterpriseAuth\\\\Plugin\\\\';\n\tif (0 !== strpos(\$class, \$prefix)) {\n\t\treturn;\n\t}\n\n\t\$relative = substr(\$class, strlen(\$prefix));\n\t\$file = {$source_root} . str_replace('\\\\', '/', \$relative) . '.php';\n\tif (is_file(\$file)) {\n\t\trequire \$file;\n\t}\n});\n"
);

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', $temp_dir );
}

$GLOBALS['ea_bootstrap_actions'] = array();

function plugin_dir_path( string $file ): string {
	return dirname( $file ) . '/';
}

function plugin_dir_url( string $file ): string {
	return 'https://example.test/wp-content/plugins/' . basename( dirname( $file ) ) . '/';
}

function add_action( string $hook, callable $callback ): void {
	$GLOBALS['ea_bootstrap_actions'][ $hook ][] = $callback;
}

function esc_html__( string $text, string $domain = 'default' ): string {
	return $text;
}

function register_activation_hook( string $file, callable $callback ): void {
	$GLOBALS['ea_activation_hook_registered'] = true;
}

ob_start();
require $temp_dir . '/enterprise-iam.php';
$bootstrap_output = ob_get_clean();

if ( '' !== $bootstrap_output ) {
	fwrite( STDERR, "FAIL: Missing Composer package should not emit frontend output.\n" );
	exit( 1 );
}

$notices = $GLOBALS['ea_bootstrap_actions']['admin_notices'] ?? array();
if ( 1 !== count( $notices ) ) {
	fwrite( STDERR, "FAIL: Expected one admin notice for missing Composer dependencies.\n" );
	exit( 1 );
}

ob_start();
$notices[0]();
$notice_output = ob_get_clean();

if ( false === strpos( $notice_output, 'Enterprise Auth could not load its Composer dependencies' ) ) {
	fwrite( STDERR, "FAIL: Expected Composer dependency notice text.\n" );
	exit( 1 );
}

if ( ! empty( $GLOBALS['ea_activation_hook_registered'] ) ) {
	fwrite( STDERR, "FAIL: Plugin must not register activation hooks after dependency load failure.\n" );
	exit( 1 );
}

fwrite( STDOUT, "PASS: Bootstrap handles missing Composer packages without a fatal error.\n" );