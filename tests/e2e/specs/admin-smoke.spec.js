const { test, expect } = require( '@playwright/test' );
const { loginToWpAdmin, openEnterpriseAuthAdmin } = require( '../utils/auth' );

test( 'network admin can open the Enterprise Auth settings screen', async ( { page } ) => {
	await loginToWpAdmin( page );
	await openEnterpriseAuthAdmin( page );

	await expect( page.getByRole( 'button', { name: 'General & Passkeys' } ) ).toBeVisible();
	await expect( page.getByRole( 'button', { name: 'Enterprise SSO (SAML)' } ) ).toBeVisible();
	await expect( page.getByRole( 'button', { name: 'Enterprise SSO (OIDC)' } ) ).toBeVisible();
	await expect( page.getByRole( 'button', { name: 'SCIM Provisioning' } ) ).toBeVisible();
	await expect( page.getByRole( 'button', { name: 'Register Passkey' } ) ).toBeVisible();
} );