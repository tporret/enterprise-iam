const { test, expect } = require( '@playwright/test' );
const { loginToWpAdmin, openEnterpriseAuthAdmin } = require( '../utils/auth' );
const { loadJsonFixture } = require( '../utils/fixtures' );

async function scimFetch( page, path, token, method = 'GET', body = null ) {
	return page.evaluate(
		async ( { requestPath, bearerToken, requestMethod, requestBody } ) => {
			const response = await window.fetch( requestPath, {
				method: requestMethod,
				headers: {
					Authorization: `Bearer ${ bearerToken }`,
					'Content-Type': 'application/scim+json',
				},
				body: null === requestBody ? undefined : JSON.stringify( requestBody ),
			} );

			let data = null;
			try {
				data = await response.json();
			} catch ( error ) {
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
			bearerToken: token,
			requestMethod: method,
			requestBody: body,
		}
	);
}

test( 'can generate a SCIM token and run a minimal user lifecycle smoke test', async ( { page } ) => {
	const runId = Date.now();
	const createPayload = loadJsonFixture( 'scim-user-create.json', { RUN_ID: runId } );
	const suspendPayload = loadJsonFixture( 'scim-user-suspend.json' );

	await loginToWpAdmin( page );
	await openEnterpriseAuthAdmin( page );
	await page.getByRole( 'button', { name: 'SCIM Provisioning' } ).click();
	await page.getByRole( 'button', { name: 'Generate New SCIM Token' } ).click();

	const tokenInput = page.locator( '.ea-scim-token-result input' );
	await expect( tokenInput ).toBeVisible();
	const token = await tokenInput.inputValue();

	let userId = null;

	try {
		const createResponse = await scimFetch(
			page,
			'/wp-json/enterprise-auth/v1/scim/v2/Users',
			token,
			'POST',
			createPayload
		);
		expect( createResponse.status ).toBe( 201 );

		const createdUser = createResponse.data;
		userId = String( createdUser.id );

		const suspendResponse = await scimFetch(
			page,
			`/wp-json/enterprise-auth/v1/scim/v2/Users/${ userId }`,
			token,
			'PATCH',
			suspendPayload
		);
		expect( suspendResponse.ok ).toBeTruthy();

		const getResponse = await scimFetch(
			page,
			`/wp-json/enterprise-auth/v1/scim/v2/Users/${ userId }`,
			token,
			'GET'
		);
		expect( getResponse.ok ).toBeTruthy();

		const fetchedUser = getResponse.data;
		expect( String( fetchedUser.id ) ).toBe( userId );
	} finally {
		if ( userId ) {
			await scimFetch(
				page,
				`/wp-json/enterprise-auth/v1/scim/v2/Users/${ userId }`,
				token,
				'DELETE'
			);
		}
	}
} );