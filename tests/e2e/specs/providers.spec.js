const { test, expect } = require( '@playwright/test' );
const { loginToWpAdmin, openEnterpriseAuthAdmin } = require( '../utils/auth' );
const { loadJsonFixture, loadTextFixture } = require( '../utils/fixtures' );
const { deleteIdpsByPrefix, pluginRest } = require( '../utils/plugin-api' );

test.describe( 'provider fixtures', () => {
	test( 'can seed OIDC and SAML providers from fixture payloads', async ( { page } ) => {
		const runId = Date.now();
		const oidcFixture = loadJsonFixture( 'oidc-idp.json', { RUN_ID: runId } );
		const samlFixture = loadJsonFixture( 'saml-idp.json', { RUN_ID: runId } );
		const createdIds = [];

		await loginToWpAdmin( page );
		await openEnterpriseAuthAdmin( page );
		await deleteIdpsByPrefix( page, 'E2E ' );

		try {
			let response = await pluginRest( page, 'idps', {
				method: 'POST',
				body: oidcFixture,
			} );
			expect( response.status ).toBe( 200 );
			createdIds.push( response.data.id );

			response = await pluginRest( page, 'idps', {
				method: 'POST',
				body: samlFixture,
			} );
			expect( response.status ).toBe( 200 );
			createdIds.push( response.data.id );

			await page.reload();
			await page.getByRole( 'button', { name: 'Enterprise SSO (OIDC)' } ).click();
			await expect( page.getByText( oidcFixture.provider_name ) ).toBeVisible();

			await page.getByRole( 'button', { name: 'Enterprise SSO (SAML)' } ).click();
			await expect( page.getByText( samlFixture.provider_name ) ).toBeVisible();
		} finally {
			for ( const id of createdIds ) {
				await pluginRest( page, `idps/${ id }`, { method: 'DELETE' } );
			}
		}
	} );

	test( 'ships a usable SAML metadata fixture for manual import flows', async () => {
		const xml = loadTextFixture( 'saml-idp-metadata.xml', { RUN_ID: 'fixture' } );

		expect( xml ).toContain( '<EntityDescriptor' );
		expect( xml ).toContain( 'SingleSignOnService' );
		expect( xml ).toContain( 'X509Certificate' );
	} );
} );