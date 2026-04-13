const { test, expect } = require( '@playwright/test' );
const env = require( '../utils/env' );
const { clearAuthCookies, loginToWpAdmin, openEnterpriseAuthAdmin } = require( '../utils/auth' );
const { loadJsonFixture } = require( '../utils/fixtures' );
const { attachVirtualAuthenticator, detachVirtualAuthenticator } = require( '../utils/webauthn' );

test( 'can register a passkey and use it on the login screen', async ( { page, browserName } ) => {
	test.skip( browserName !== 'chromium', 'Virtual WebAuthn coverage requires Chromium.' );
	test.slow();

	const passkeyUser = loadJsonFixture( 'passkey-user.json', {
		NETWORK_ADMIN_EMAIL: env.networkAdmin.email,
	} );
	const authenticator = await attachVirtualAuthenticator( page );

	try {
		await loginToWpAdmin( page );
		await openEnterpriseAuthAdmin( page );
		const registrationResponsePromise = page.waitForResponse( ( response ) => {
			return response.url().includes( '/wp-json/enterprise-auth/v1/passkeys/register' )
				&& response.request().method() === 'POST';
		} );

		await page.getByRole( 'button', { name: 'Register Passkey' } ).click();

		const registrationResponse = await registrationResponsePromise;
		expect( registrationResponse.status() ).toBe( 200 );
		expect( await registrationResponse.json() ).toMatchObject( {
			success: true,
		} );

		await clearAuthCookies( page );
		await page.goto( '/wp-login.php' );
		await page.locator( '#user_login' ).fill( passkeyUser.email );
		await page.locator( '#ea-route-btn' ).click();
		await expect( page.locator( '#ea-passkey-login-btn' ) ).toBeVisible();

		const loginResponsePromise = page.waitForResponse( ( response ) => {
			return response.url().includes( '/wp-json/enterprise-auth/v1/passkeys/login' )
				&& response.request().method() === 'POST';
		} );

		await page.locator( '#ea-passkey-login-btn' ).click();

		const loginResponse = await loginResponsePromise;
		expect( loginResponse.status() ).toBe( 200 );

		await expect( page ).toHaveURL( /\/wp-admin(?:\/|\?|$)/ );
	} finally {
		await detachVirtualAuthenticator( authenticator );
	}
} );