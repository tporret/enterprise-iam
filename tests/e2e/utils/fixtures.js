const fs = require( 'fs' );
const path = require( 'path' );

function fixturePath( name ) {
	return path.join( __dirname, '../fixtures', name );
}

function applyReplacements( text, replacements = {} ) {
	let hydrated = text;

	for ( const [ key, value ] of Object.entries( replacements ) ) {
		hydrated = hydrated.replaceAll( `__${ key }__`, String( value ) );
	}

	return hydrated;
}

function loadTextFixture( name, replacements = {} ) {
	const raw = fs.readFileSync( fixturePath( name ), 'utf8' );
	return applyReplacements( raw, replacements );
}

function loadJsonFixture( name, replacements = {} ) {
	return JSON.parse( loadTextFixture( name, replacements ) );
}

module.exports = {
	loadJsonFixture,
	loadTextFixture,
};