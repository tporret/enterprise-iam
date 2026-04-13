const path = require( 'path' );
const dotenv = require( 'dotenv' );
const { defineConfig, devices } = require( '@playwright/test' );

dotenv.config( {
	path: path.join( __dirname, '.env.e2e' ),
} );

module.exports = defineConfig( {
	testDir: path.join( __dirname, 'tests/e2e/specs' ),
	fullyParallel: false,
	workers: 1,
	timeout: 60_000,
	expect: {
		timeout: 10_000,
	},
	reporter: [
		[ 'list' ],
		[ 'html', { open: 'never', outputFolder: 'playwright-report' } ],
	],
	outputDir: 'test-results/playwright',
	use: {
		baseURL: process.env.E2E_BASE_URL || 'https://secaudit.localhost',
		ignoreHTTPSErrors: true,
		trace: 'retain-on-failure',
		screenshot: 'only-on-failure',
		video: 'retain-on-failure',
	},
	projects: [
		{
			name: 'chromium',
			use: {
				...devices[ 'Desktop Chrome' ],
			},
		},
	],
} );