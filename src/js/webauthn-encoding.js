/**
 * Encode an ArrayBuffer to a Base64URL string.
 *
 * @param {ArrayBuffer} buffer
 * @return {string}
 */
export function bufferToBase64url( buffer ) {
	const bytes = new Uint8Array( buffer );
	let binary = '';

	for ( let i = 0; i < bytes.length; i++ ) {
		binary += String.fromCharCode( bytes[ i ] );
	}

	return btoa( binary )
		.replace( /\+/g, '-' )
		.replace( /\//g, '_' )
		.replace( /=+$/g, '' );
}

/**
 * Decode a Base64URL string to an ArrayBuffer.
 *
 * @param {string} base64url
 * @return {ArrayBuffer}
 */
export function base64urlToBuffer( base64url ) {
	const base64 = base64url.replace( /-/g, '+' ).replace( /_/g, '/' );
	const padded = base64 + '='.repeat( ( 4 - ( base64.length % 4 ) ) % 4 );
	const binary = atob( padded );
	const bytes = new Uint8Array( binary.length );

	for ( let i = 0; i < binary.length; i++ ) {
		bytes[ i ] = binary.charCodeAt( i );
	}

	return bytes.buffer;
}