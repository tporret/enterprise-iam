import apiFetch from '@wordpress/api-fetch';
import { base64urlToBuffer, bufferToBase64url } from './webauthn-encoding';

let installed = false;
let pendingStepUp = null;

function isStepUpRequired( error ) {
	return error?.code === 'passkey_step_up_required' || error?.data?.code === 'passkey_step_up_required';
}

function isStepUpRequest( options ) {
	const path = options?.path || '';
	return typeof path === 'string' && path.includes( 'enterprise-auth/v1/passkeys/step-up' );
}

function optionsToPublicKey( options ) {
	const publicKey = {
		challenge: base64urlToBuffer( options.challenge ),
		rpId: options.rpId,
		timeout: options.timeout,
		userVerification: options.userVerification || 'required',
	};

	if ( Array.isArray( options.allowCredentials ) && options.allowCredentials.length > 0 ) {
		publicKey.allowCredentials = options.allowCredentials.map( ( credential ) => ( {
			type: credential.type,
			id: base64urlToBuffer( credential.id ),
			transports: credential.transports || [],
		} ) );
	}

	return publicKey;
}

async function confirmStepUp() {
	if ( ! window.PublicKeyCredential ) {
		throw new Error( 'This browser cannot confirm passkeys for high-risk actions.' );
	}

	const options = await apiFetch( {
		path: 'enterprise-auth/v1/passkeys/step-up',
	} );
	const credential = await navigator.credentials.get( {
		publicKey: optionsToPublicKey( options ),
	} );

	const payload = {
		id: credential.id,
		rawId: bufferToBase64url( credential.rawId ),
		type: credential.type,
		response: {
			clientDataJSON: bufferToBase64url( credential.response.clientDataJSON ),
			authenticatorData: bufferToBase64url( credential.response.authenticatorData ),
			signature: bufferToBase64url( credential.response.signature ),
		},
		session_key: options.session_key,
	};

	if ( credential.response.userHandle ) {
		payload.response.userHandle = bufferToBase64url( credential.response.userHandle );
	}

	await apiFetch( {
		path: 'enterprise-auth/v1/passkeys/step-up',
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify( payload ),
	} );
}

function stepUpMessage( error ) {
	return error?.data?.error || error?.message || 'Passkey confirmation failed. Try the action again.';
}

export function installStepUpApiFetchMiddleware() {
	if ( installed ) {
		return;
	}

	installed = true;
	apiFetch.use( async ( options, next ) => {
		try {
			return await next( options );
		} catch ( error ) {
			if ( ! isStepUpRequired( error ) || options.__enterpriseAuthStepUpRetried || isStepUpRequest( options ) ) {
				throw error;
			}

			try {
				pendingStepUp = pendingStepUp || confirmStepUp();
				await pendingStepUp;
			} catch ( stepUpError ) {
				throw new Error( stepUpMessage( stepUpError ) );
			} finally {
				pendingStepUp = null;
			}

			return next( {
				...options,
				__enterpriseAuthStepUpRetried: true,
			} );
		}
	} );
}