const { test, expect } = require( '@playwright/test' );
const env = require( '../utils/env' );
const { loginToWpAdmin, openEnterpriseAuthAdmin } = require( '../utils/auth' );

async function openNetworkScreen( page, slug ) {
	await page.goto( `/wp-admin/network/admin.php?page=${ slug }` );
	await expect( page.getByRole( 'heading', { name: 'Enterprise Auth' } ) ).toBeVisible();
	await page.waitForLoadState( 'networkidle' );
}

async function loginToSiteAdmin( page, loginUrl, credentials ) {
	await page.goto( loginUrl );
	await page.locator( '#user_login' ).fill( credentials.email );
	await page.locator( '#ea-route-btn' ).click();
	await expect( page.locator( '#user_pass' ) ).toBeVisible();
	await page.locator( '#user_pass' ).fill( credentials.password );
	await page.getByRole( 'button', { name: /^log in$/i } ).click();
	await expect( page ).toHaveURL( /\/wp-admin(?:\/|\?|$)/ );
	await page.waitForLoadState( 'networkidle' );
}

test( 'network admin can open the Enterprise Auth settings screen', async ( { page } ) => {
	await loginToWpAdmin( page );
	await openEnterpriseAuthAdmin( page );

	await expect( page.getByRole( 'button', { name: 'General & Passkeys' } ) ).toBeVisible();
	await expect( page.getByRole( 'button', { name: 'Enterprise SSO (SAML)' } ) ).toBeVisible();
	await expect( page.getByRole( 'button', { name: 'Enterprise SSO (OIDC)' } ) ).toBeVisible();
	await expect( page.getByRole( 'button', { name: 'SCIM Provisioning' } ) ).toBeVisible();
	await expect( page.getByRole( 'button', { name: 'Register Passkey' } ) ).toBeVisible();
} );

test( 'network admin can open multisite dashboard screens', async ( { page } ) => {
	const pageErrors = [];

	page.on( 'pageerror', ( error ) => {
		pageErrors.push( error.message );
	} );

	await loginToWpAdmin( page );

	await test.step( 'overview renders', async () => {
		await openNetworkScreen( page, 'enterprise-auth-network' );

		await expect( page.getByText( 'Network control plane for multisite identity and access management' ) ).toBeVisible();
		await expect( page.getByRole( 'button', { name: 'Overview' } ) ).toBeVisible();
		await expect( page.getByRole( 'button', { name: 'Identity Providers' } ) ).toBeVisible();
		await expect( page.getByRole( 'button', { name: 'Site Assignments' } ) ).toBeVisible();
		await expect( page.getByRole( 'button', { name: 'Defaults & Policy' } ) ).toBeVisible();
		await expect( page.getByRole( 'heading', { name: 'Provider Inventory' } ) ).toBeVisible();
		await expect( page.getByRole( 'heading', { name: 'Sites Missing Assignments' } ) ).toBeVisible();
	} );

	await test.step( 'providers screen renders', async () => {
		await openNetworkScreen( page, 'enterprise-auth-network-providers' );

		await expect( page.getByRole( 'button', { name: 'SAML', exact: true } ) ).toBeVisible();
		await expect( page.getByRole( 'button', { name: 'OIDC', exact: true } ) ).toBeVisible();
		await expect( page.getByRole( 'heading', { name: 'SAML Identity Providers' } ) ).toBeVisible();
	} );

	await test.step( 'assignments screen renders', async () => {
		await openNetworkScreen( page, 'enterprise-auth-network-assignments' );

		await expect(
			page.getByRole( 'heading', { name: /Assignment Model|Site Assignments/ } )
		).toBeVisible();
	} );

	await test.step( 'defaults and policy screen renders', async () => {
		await openNetworkScreen( page, 'enterprise-auth-network-policy' );

		await expect( page.getByRole( 'heading', { name: 'Defaults and Policy' } ) ).toBeVisible();
		await expect( page.getByText( 'Allow Site Override: Enterprise Lockdown Mode' ) ).toBeVisible();
		await expect( page.getByText( 'Allow Site Role Mappings' ) ).toBeVisible();
	} );

	expect( pageErrors, `Unexpected page errors: ${ pageErrors.join( '; ' ) }` ).toEqual( [] );
} );

test( 'site admin sees network-enforced policy state', async ( { page } ) => {
	const pageErrors = [];
	const siteOwnerLoginUrl = 'https://app.secaudit.localhost/wp-login.php';
	const siteOwnerAdminUrl = 'https://app.secaudit.localhost/wp-admin/admin.php?page=enterprise-auth';

	page.on( 'pageerror', ( error ) => {
		pageErrors.push( error.message );
	} );

	await loginToSiteAdmin( page, siteOwnerLoginUrl, env.siteOwner );
	await page.goto( siteOwnerAdminUrl );
	await expect( page.getByRole( 'heading', { name: 'Enterprise Auth' } ) ).toBeVisible();
	await page.waitForLoadState( 'networkidle' );

	const lockdownCard = page.locator( '.ea-card' ).filter( {
		has: page.getByRole( 'heading', { name: 'Enterprise Lockdown Mode' } ),
	} ).first();
	await expect( lockdownCard.getByText( 'Locked by Network Policy' ) ).toBeVisible();
	await expect( lockdownCard.locator( 'input[type="checkbox"]' ) ).toBeDisabled();

	const sessionTimeoutCard = page.locator( '.ea-card' ).filter( {
		has: page.getByRole( 'heading', { name: 'SSO Session Timeout' } ),
	} ).first();
	const sessionTimeoutSelect = sessionTimeoutCard.locator( 'select' );

	await expect( sessionTimeoutCard.getByText( 'Inherited from Network' ) ).toBeVisible();
	await expect( sessionTimeoutSelect ).toBeEnabled();

	const lockedResponse = await page.evaluate( async () => {
		const response = await window.fetch( window.enterpriseAuth.restUrl + 'settings', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-WP-Nonce': window.enterpriseAuth.nonce,
			},
			credentials: 'same-origin',
			body: JSON.stringify( { lockdown_mode: false } ),
		} );

		return {
			status: response.status,
			body: await response.json(),
		};
	} );

	expect( lockedResponse.status ).toBe( 403 );
	expect( lockedResponse.body.code ).toBe( 'locked_by_network_policy' );
	expect( lockedResponse.body.locked_fields ).toContain( 'lockdown_mode' );

	await sessionTimeoutSelect.selectOption( '12' );
	await expect( page.getByText( 'Settings saved successfully.' ) ).toBeVisible();
	await expect( sessionTimeoutCard.getByText( 'Overridden on This Site' ) ).toBeVisible();

	await sessionTimeoutSelect.selectOption( '8' );
	await expect( page.getByText( 'Settings saved successfully.' ) ).toBeVisible();
	await expect( sessionTimeoutCard.getByText( 'Inherited from Network' ) ).toBeVisible();

	expect( pageErrors, `Unexpected page errors: ${ pageErrors.join( '; ' ) }` ).toEqual( [] );
} );

test( 'users list and profile expose Enterprise Auth visibility', async ( { page } ) => {
	const pageErrors = [];

	page.on( 'pageerror', ( error ) => {
		pageErrors.push( error.message );
	} );

	await loginToWpAdmin( page );
	await page.goto( '/wp-admin/users.php' );
	const usersTableHead = page.locator( '.wp-list-table thead' );
	await expect( usersTableHead.getByRole( 'columnheader', { name: 'Identity' } ) ).toBeVisible();
	await expect( usersTableHead.getByRole( 'columnheader', { name: 'Provider' } ) ).toBeVisible();
	await expect( usersTableHead.getByRole( 'columnheader', { name: 'Passkeys' } ) ).toBeVisible();
	await expect( usersTableHead.getByRole( 'columnheader', { name: 'State' } ) ).toBeVisible();

	const auditAdminRow = page.locator( '#the-list tr' ).filter( {
		has: page.locator( 'strong >> text=auditadmin' ),
	} ).first();

	await expect( auditAdminRow ).toBeVisible();
	await expect( auditAdminRow.locator( 'td.column-enterprise_auth_identity' ) ).toContainText( 'Local' );
	await expect( auditAdminRow.locator( 'td.column-enterprise_auth_provider' ) ).toContainText( 'Local' );
	await expect( auditAdminRow.locator( 'td.column-enterprise_auth_state' ) ).toContainText( 'Active' );
	await expect( auditAdminRow.locator( 'td.column-enterprise_auth_passkeys' ) ).toContainText( /(compliant|legacy|total|None)/ );

	await page.goto( '/wp-admin/profile.php' );
	await expect( page.getByRole( 'heading', { name: 'Enterprise Auth' } ) ).toBeVisible();
	await expect( page.getByText( 'Current Site Context' ) ).toBeVisible();
	await expect( page.getByText( 'Identity Source' ) ).toBeVisible();
	await expect( page.getByText( 'Passkey Counts' ) ).toBeVisible();
	await expect( page.getByText( /total \/ .* compliant \/ .* legacy/ ) ).toBeVisible();

	expect( pageErrors, `Unexpected page errors: ${ pageErrors.join( '; ' ) }` ).toEqual( [] );
} );

test( 'site admin profile visibility uses the current subsite context', async ( { page } ) => {
	const pageErrors = [];
	const siteOwnerLoginUrl = 'https://app.secaudit.localhost/wp-login.php';

	page.on( 'pageerror', ( error ) => {
		pageErrors.push( error.message );
	} );

	await loginToSiteAdmin( page, siteOwnerLoginUrl, env.siteOwner );
	await page.goto( 'https://app.secaudit.localhost/wp-admin/users.php' );
	const subsiteUsersTableHead = page.locator( '.wp-list-table thead' );
	await expect( subsiteUsersTableHead.getByRole( 'columnheader', { name: 'Identity' } ) ).toBeVisible();
	await expect( subsiteUsersTableHead.getByRole( 'columnheader', { name: 'Provider' } ) ).toBeVisible();

	const siteOwnerRow = page.locator( '#the-list tr' ).filter( {
		has: page.locator( 'strong >> text=siteowner' ),
	} ).first();

	await expect( siteOwnerRow ).toBeVisible();
	await expect( siteOwnerRow.locator( 'td.column-enterprise_auth_identity' ) ).toContainText( 'Local' );
	await expect( siteOwnerRow.locator( 'td.column-enterprise_auth_provider' ) ).toContainText( 'Local' );
	await expect( siteOwnerRow.locator( 'td.column-enterprise_auth_passkeys' ) ).toContainText( 'None' );

	await page.goto( 'https://app.secaudit.localhost/wp-admin/profile.php' );
	await expect( page.getByRole( 'heading', { name: 'Enterprise Auth' } ) ).toBeVisible();
	await expect( page.getByText( 'Current Site Context' ) ).toBeVisible();
	await expect( page.getByText( 'app.secaudit.localhost' ) ).toBeVisible();
	const identitySourceRow = page.locator( 'tr' ).filter( {
		has: page.getByText( 'Identity Source' ),
	} ).first();
	await expect( identitySourceRow ).toContainText( 'Local' );
	await expect( page.getByText( 'Not Required' ) ).toBeVisible();

	expect( pageErrors, `Unexpected page errors: ${ pageErrors.join( '; ' ) }` ).toEqual( [] );
} );