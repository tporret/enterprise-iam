async function attachVirtualAuthenticator( page ) {
	const client = await page.context().newCDPSession( page );
	await client.send( 'WebAuthn.enable' );

	const { authenticatorId } = await client.send(
		'WebAuthn.addVirtualAuthenticator',
		{
			options: {
				protocol: 'ctap2',
				transport: 'internal',
				hasResidentKey: true,
				hasUserVerification: true,
				isUserVerified: true,
				automaticPresenceSimulation: true,
			},
		}
	);

	return {
		authenticatorId,
		client,
	};
}

async function detachVirtualAuthenticator( handle ) {
	if ( ! handle || ! handle.client || ! handle.authenticatorId ) {
		return;
	}

	try {
		await handle.client.send( 'WebAuthn.removeVirtualAuthenticator', {
			authenticatorId: handle.authenticatorId,
		} );
		await handle.client.send( 'WebAuthn.disable' );
	} catch ( error ) {
		// Ignore teardown failures when the page or browser already closed.
	}
}

module.exports = {
	attachVirtualAuthenticator,
	detachVirtualAuthenticator,
};