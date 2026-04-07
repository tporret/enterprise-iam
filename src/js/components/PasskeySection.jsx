import { useState, useCallback } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

/**
 * Encode an ArrayBuffer to a Base64URL string.
 */
function bufferToBase64url( buffer ) {
	const bytes = new Uint8Array( buffer );
	let binary = '';
	for ( let i = 0; i < bytes.length; i++ ) {
		binary += String.fromCharCode( bytes[ i ] );
	}
	return btoa( binary )
		.replace( /\+/g, '-' )
		.replace( /\//g, '_' )
		.replace( /=+$/, '' );
}

/**
 * Decode a Base64URL string to an ArrayBuffer.
 */
function base64urlToBuffer( base64url ) {
	const base64 = base64url.replace( /-/g, '+' ).replace( /_/g, '/' );
	const padded = base64 + '='.repeat( ( 4 - ( base64.length % 4 ) ) % 4 );
	const binary = atob( padded );
	const bytes = new Uint8Array( binary.length );
	for ( let i = 0; i < binary.length; i++ ) {
		bytes[ i ] = binary.charCodeAt( i );
	}
	return bytes.buffer;
}

export default function PasskeySection( { showToast } ) {
	const [ registering, setRegistering ] = useState( false );

	const registerPasskey = useCallback( async () => {
		if ( ! window.PublicKeyCredential ) {
			showToast( 'WebAuthn is not supported by this browser.', 'error' );
			return;
		}

		setRegistering( true );

		try {
			// 1. Fetch creation options from the server.
			const options = await apiFetch( {
				path: 'enterprise-auth/v1/passkeys/register',
			} );

			// 2. Convert the server options into the format expected by the browser.
			const publicKey = {
				...options,
				challenge: base64urlToBuffer( options.challenge ),
				user: {
					...options.user,
					id: base64urlToBuffer( options.user.id ),
				},
			};

			if ( publicKey.excludeCredentials ) {
				publicKey.excludeCredentials = publicKey.excludeCredentials.map(
					( cred ) => ( {
						...cred,
						id: base64urlToBuffer( cred.id ),
					} )
				);
			}

			// 3. Create the credential via the browser WebAuthn API.
			const credential = await navigator.credentials.create( {
				publicKey,
			} );

			// 4. Serialize the response back to the server.
			const attestationResponse = {
				id: credential.id,
				rawId: bufferToBase64url( credential.rawId ),
				type: credential.type,
				response: {
					clientDataJSON: bufferToBase64url(
						credential.response.clientDataJSON
					),
					attestationObject: bufferToBase64url(
						credential.response.attestationObject
					),
				},
			};

			if ( credential.response.getTransports ) {
				attestationResponse.response.transports =
					credential.response.getTransports();
			}

			// 5. POST the attestation to the server for verification.
			const result = await apiFetch( {
				path: 'enterprise-auth/v1/passkeys/register',
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify( attestationResponse ),
			} );

			if ( result.success ) {
				showToast( 'Passkey registered successfully!' );
			} else {
				showToast( result.error || 'Registration failed.', 'error' );
			}
		} catch ( err ) {
			if ( err.name === 'NotAllowedError' ) {
				showToast( 'Passkey registration was cancelled.', 'error' );
			} else {
				showToast(
					'Passkey registration failed: ' + err.message,
					'error'
				);
			}
		} finally {
			setRegistering( false );
		}
	}, [ showToast ] );

	return (
		<div className="ea-card">
			<div className="ea-card__body ea-card__body--passkey">
				<div className="ea-card__text">
					<h2 className="ea-card__title">Passkey Authentication</h2>
					<p className="ea-card__desc">
						Register a passkey to enable passwordless login using
						biometrics, security keys, or your device PIN.
					</p>
				</div>
				<button
					type="button"
					className="ea-btn ea-btn--primary"
					onClick={ registerPasskey }
					disabled={ registering }
				>
					{ registering ? 'Registering…' : 'Register Passkey' }
				</button>
			</div>
		</div>
	);
}
