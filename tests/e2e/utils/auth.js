const { expect } = require( '@playwright/test' );
const env = require( './env' );

async function loginToWpAdmin( page, credentials = env.networkAdmin ) {
	await page.goto( '/wp-login.php' );
	await page.locator( '#user_login' ).fill( credentials.email );
	await page.locator( '#ea-route-btn' ).click();
	await expect( page.locator( '#user_pass' ) ).toBeVisible();
	await page.locator( '#user_pass' ).fill( credentials.password );
	await page.getByRole( 'button', { name: /^log in$/i } ).click();
	await expect( page ).toHaveURL( /\/wp-admin(?:\/|\?|$)/ );
	await page.waitForLoadState( 'networkidle' );
}

async function openEnterpriseAuthAdmin( page ) {
	await page.goto( '/wp-admin/admin.php?page=enterprise-auth' );
	await expect( page.getByRole( 'heading', { name: 'Enterprise Auth' } ) ).toBeVisible();
	await page.waitForLoadState( 'networkidle' );
}

async function clearAuthCookies( page ) {
	await page.context().clearCookies();
}

module.exports = {
	clearAuthCookies,
	loginToWpAdmin,
	openEnterpriseAuthAdmin,
};