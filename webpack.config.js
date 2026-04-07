const defaultConfig = require( '@wordpress/scripts/config/webpack.config' );
const path = require( 'path' );

module.exports = {
	...defaultConfig,
	entry: {
		index: path.resolve( __dirname, 'src/js/index.js' ),
		'passkey-login': path.resolve( __dirname, 'src/js/passkey-login.js' ),
	},
	output: {
		...defaultConfig.output,
		path: path.resolve( __dirname, 'build' ),
	},
};
