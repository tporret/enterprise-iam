const { test, expect } = require( '@playwright/test' );
const { loginToWpAdmin, openEnterpriseAuthAdmin } = require( '../utils/auth' );

async function openNetworkScreen( page, slug ) {
	await page.goto( `/wp-admin/network/admin.php?page=${ slug }` );
	await expect( page.getByRole( 'heading', { name: 'Enterprise Auth' } ) ).toBeVisible();
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