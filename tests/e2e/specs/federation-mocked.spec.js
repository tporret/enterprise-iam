const zlib = require( 'zlib' );
const { test, expect } = require( '@playwright/test' );
const { loginToWpAdmin, openEnterpriseAuthAdmin, clearAuthCookies } = require( '../utils/auth' );
const { loadJsonFixture } = require( '../utils/fixtures' );
const { deleteIdpsByPrefix, pluginRest } = require( '../utils/plugin-api' );

function decodeSamlRequest( encodedRequest ) {
	return zlib.inflateRawSync( Buffer.from( encodedRequest, 'base64' ) ).toString( 'utf8' );
}

async function seedProvider( page, fixture ) {
	const response = await pluginRest( page, 'idps', {
		method: 'POST',
		body: fixture,
	} );

	expect( response.status ).toBe( 200 );
	return response.data;
}

async function goToLoginAsSsoUser( page, email ) {
	await clearAuthCookies( page );
	await page.goto( '/wp-login.php' );
	await page.locator( '#user_login' ).fill( email );
	await page.locator( '#ea-route-btn' ).click();
}

async function cleanupProvider( page, idpId ) {
	if ( ! idpId ) {
		return;
	}

	await loginToWpAdmin( page );
	await openEnterpriseAuthAdmin( page );
	await pluginRest( page, `idps/${ idpId }`, { method: 'DELETE' } );
}

async function fetchSamlMetadata( page ) {
	return page.evaluate( async () => {
		const response = await window.fetch( '/wp-json/enterprise-auth/v1/saml/metadata' );
		const text = await response.text();

		return {
			status: response.status,
			contentType: response.headers.get( 'content-type' ) || '',
			text,
		};
	} );
}

test.describe( 'mocked federation flows', () => {
	test( 'OIDC login builds the authorization redirect and handles provider errors on callback', async ( { page } ) => {
		const runId = Date.now();
		const email = `user@oidc-${ runId }.example.com`;
		const fixture = {
			...loadJsonFixture( 'oidc-idp.json', { RUN_ID: runId } ),
			force_reauth: true,
			domain_mapping: [ `oidc-${ runId }.example.com` ],
		};
		let idpId = null;

		await loginToWpAdmin( page );
		await openEnterpriseAuthAdmin( page );
		await deleteIdpsByPrefix( page, 'E2E ' );

		try {
			const created = await seedProvider( page, fixture );
			idpId = created.id;

			await page.route( 'https://example.com/**', async ( route ) => {
				await route.fulfill( {
					status: 200,
					contentType: 'text/html',
					body: '<html><body>Mock OIDC Provider</body></html>',
				} );
			} );

			await goToLoginAsSsoUser( page, email );
			await page.waitForURL( ( url ) => url.hostname === 'example.com' && url.pathname.includes( `/e2e/oidc/${ runId }/oauth2/authorize` ) );

			const authUrl = new URL( page.url() );
			expect( `${ authUrl.origin }${ authUrl.pathname }` ).toBe( `https://example.com/e2e/oidc/${ runId }/oauth2/authorize` );
			expect( authUrl.searchParams.get( 'response_type' ) ).toBe( 'code' );
			expect( authUrl.searchParams.get( 'client_id' ) ).toBe( fixture.client_id );
			expect( authUrl.searchParams.get( 'scope' ) ).toBe( 'openid email profile' );
			expect( authUrl.searchParams.get( 'code_challenge_method' ) ).toBe( 'S256' );
			expect( authUrl.searchParams.get( 'prompt' ) ).toBe( 'login' );
			expect( authUrl.searchParams.get( 'state' ) ).toMatch( /^[a-f0-9]{32}$/ );
			expect( authUrl.searchParams.get( 'nonce' ) ).toMatch( /^[a-f0-9]{32}$/ );
			expect( authUrl.searchParams.get( 'code_challenge' ) ).toBeTruthy();

			const callbackState = authUrl.searchParams.get( 'state' );
			await page.goto( `/wp-json/enterprise-auth/v1/oidc/callback?error=access_denied&error_description=user_cancelled&state=${ callbackState }` );

			await expect( page ).toHaveURL( /\/wp-login\.php\?[^\s]*sso_error=federation_failed/ );
			await expect( page.locator( '#login_error' ) ).toContainText( 'SSO Error:' );
			await expect( page.locator( '.ea-sso-error-reference' ) ).toContainText( 'Reference ID:' );
		} finally {
			await cleanupProvider( page, idpId );
		}
	} );

	test( 'SAML login builds an AuthnRequest, serves metadata, and handles invalid ACS posts', async ( { page } ) => {
		const runId = Date.now();
		const email = `user@saml-${ runId }.example.com`;
		const fixture = {
			...loadJsonFixture( 'saml-idp.json', { RUN_ID: runId } ),
			force_reauth: true,
			domain_mapping: [ `saml-${ runId }.example.com` ],
		};
		let idpId = null;

		await loginToWpAdmin( page );
		await openEnterpriseAuthAdmin( page );
		await deleteIdpsByPrefix( page, 'E2E ' );

		try {
			const created = await seedProvider( page, fixture );
			idpId = created.id;

			const metadataResponse = await fetchSamlMetadata( page );
			expect( metadataResponse.status ).toBe( 200 );
			expect( metadataResponse.contentType ).toContain( 'application/samlmetadata+xml' );
			const metadataXml = metadataResponse.text;
			expect( metadataXml ).toContain( 'EntityDescriptor' );
			expect( metadataXml ).toContain( '/wp-json/enterprise-auth/v1/saml/acs' );

			await page.route( 'https://example.com/**', async ( route ) => {
				await route.fulfill( {
					status: 200,
					contentType: 'text/html',
					body: '<html><body>Mock SAML Provider</body></html>',
				} );
			} );

			await goToLoginAsSsoUser( page, email );
			await page.waitForURL( ( url ) => url.hostname === 'example.com' && url.pathname.includes( `/e2e/saml/${ runId }/sso` ) );

			const samlRedirectUrl = new URL( page.url() );
			expect( `${ samlRedirectUrl.origin }${ samlRedirectUrl.pathname }` ).toBe( `https://example.com/e2e/saml/${ runId }/sso` );

			const relayState = samlRedirectUrl.searchParams.get( 'RelayState' );
			const samlRequest = samlRedirectUrl.searchParams.get( 'SAMLRequest' );
			expect( relayState ).toMatch( /^[a-f0-9]{32}$/ );
			expect( samlRequest ).toBeTruthy();

			const authnRequestXml = decodeSamlRequest( samlRequest );
			expect( authnRequestXml ).toContain( 'AuthnRequest' );
			expect( authnRequestXml ).toContain( 'ForceAuthn="true"' );
			expect( authnRequestXml ).toContain( '/wp-json/enterprise-auth/v1/saml/acs' );

			await page.setContent(
				`<form id="acs" method="post" action="https://secaudit.localhost/wp-json/enterprise-auth/v1/saml/acs">
					<input name="SAMLResponse" value="${ Buffer.from( 'invalid-saml-response' ).toString( 'base64' ) }" />
					<input name="RelayState" value="${ relayState }" />
				</form>`
			);
			await page.locator( '#acs' ).evaluate( ( form ) => form.submit() );

			await expect( page ).toHaveURL( /\/wp-login\.php\?[^\s]*sso_error=federation_failed/ );
			await expect( page.locator( '#login_error' ) ).toContainText( 'SSO Error:' );
			await expect( page.locator( '.ea-sso-error-reference' ) ).toContainText( 'Reference ID:' );
		} finally {
			await cleanupProvider( page, idpId );
		}
	} );
} );