const { test, expect } = require( '@playwright/test' );
const env = require( '../utils/env' );
const { clearAuthCookies, loginToWpAdmin, openEnterpriseAuthAdmin } = require( '../utils/auth' );
const { pluginRest } = require( '../utils/plugin-api' );

async function coreRest( page, path, options = {} ) {
	const method = options.method || 'GET';
	const body = Object.prototype.hasOwnProperty.call( options, 'body' )
		? options.body
		: null;

	return page.evaluate(
		async ( { requestPath, requestMethod, requestBody } ) => {
			const url = new URL( requestPath, window.location.origin ).toString();

			const response = await window.fetch( url, {
				method: requestMethod,
				headers: {
					'Content-Type': 'application/json',
					'X-WP-Nonce': window.enterpriseAuth.nonce,
				},
				body:
					null === requestBody
						? undefined
						: JSON.stringify( requestBody ),
			} );

			let data = null;
			try {
				data = await response.json();
			} catch {
				data = null;
			}

			return {
				ok: response.ok,
				status: response.status,
				data,
			};
		},
		{
			requestPath: path,
			requestMethod: method,
			requestBody: body,
		}
	);
}

test( 'private content gate redirects to login and preserves destination', async ( { page } ) => {
	const pageErrors = [];
	const runId = Date.now();
	const title = `Private Gate E2E ${ runId }`;
	let createdPostId = null;
	let createdPostUrl = '';

	page.on( 'pageerror', ( error ) => {
		pageErrors.push( error.message );
	} );

	try {
		await loginToWpAdmin( page );
		await openEnterpriseAuthAdmin( page );

		const enableGate = await pluginRest( page, 'settings', {
			method: 'POST',
			body: { private_content_login_required: true },
		} );
		expect( enableGate.status ).toBe( 200 );
		expect( enableGate.data.private_content_login_required ).toBe( true );

		const postResponse = await coreRest( page, '/wp-json/wp/v2/posts', {
			method: 'POST',
			body: {
				title,
				content: 'Private gate test content.',
				status: 'private',
			},
		} );

		expect( postResponse.status ).toBe( 201 );
		createdPostId = postResponse.data.id;
		createdPostUrl = postResponse.data.link;

		await clearAuthCookies( page );
		await page.goto( '/' );
		await expect( page ).not.toHaveURL( /\/wp-login\.php/ );
		await expect( page.locator( '#loginform' ) ).toHaveCount( 0 );

		await page.goto( createdPostUrl );
		await expect( page ).toHaveURL( /\/wp-login\.php\?/ );

		const loginUrl = new URL( page.url() );
		expect( loginUrl.searchParams.get( 'redirect_to' ) ).toBe( createdPostUrl );

		await page.locator( '#user_login' ).fill( env.networkAdmin.email );
		await page.locator( '#ea-route-btn' ).click();
		await expect( page.locator( '#user_pass' ) ).toBeVisible();
		await page.locator( '#user_pass' ).fill( env.networkAdmin.password );
		await page.getByRole( 'button', { name: /^log in$/i } ).click();

		await expect( page ).toHaveURL( createdPostUrl );
		await expect( page.getByText( title, { exact: false } ).first() ).toBeVisible();
	} finally {
		await clearAuthCookies( page );
		await loginToWpAdmin( page );
		await openEnterpriseAuthAdmin( page );

		await pluginRest( page, 'settings', {
			method: 'POST',
			body: { private_content_login_required: false },
		} );

		if ( createdPostId ) {
			await coreRest( page, `/wp-json/wp/v2/posts/${ createdPostId }?force=true`, {
				method: 'DELETE',
			} );
		}
	}

	expect( pageErrors, `Unexpected page errors: ${ pageErrors.join( '; ' ) }` ).toEqual( [] );
} );