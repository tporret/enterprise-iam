async function pluginRest( page, path, options = {} ) {
	const method = options.method || 'GET';
	const body = Object.prototype.hasOwnProperty.call( options, 'body' )
		? options.body
		: null;

	return page.evaluate(
		async ( { requestPath, requestMethod, requestBody } ) => {
			const url = new URL(
				requestPath.replace( /^\/+/, '' ),
				window.enterpriseAuth.restUrl
			).toString();

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
			requestMethod: method,
			requestBody: body,
		}
	);
}

async function deleteIdpsByPrefix( page, prefix ) {
	const listing = await pluginRest( page, 'idps' );
	if ( ! listing.ok || ! Array.isArray( listing.data ) ) {
		throw new Error( 'Failed to load IdP list for fixture cleanup.' );
	}

	for ( const idp of listing.data ) {
		if ( typeof idp.provider_name === 'string' && idp.provider_name.startsWith( prefix ) ) {
			await pluginRest( page, `idps/${ idp.id }`, { method: 'DELETE' } );
		}
	}
}

module.exports = {
	deleteIdpsByPrefix,
	pluginRest,
};