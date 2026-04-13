function getEnv( name, fallback ) {
	const value = process.env[ name ];
	if ( typeof value === 'string' && value.trim() ) {
		return value.trim();
	}

	if ( typeof fallback !== 'undefined' ) {
		return fallback;
	}

	throw new Error(
		`Missing required environment variable ${ name }. Copy .env.e2e.example to .env.e2e.`
	);
}

const env = {
	baseURL: getEnv( 'E2E_BASE_URL', 'https://secaudit.localhost' ),
	networkAdmin: {
		username: getEnv( 'E2E_NETWORK_ADMIN_USERNAME', 'auditadmin' ),
		email: getEnv( 'E2E_NETWORK_ADMIN_EMAIL', 'auditadmin@secaudit.localhost' ),
		password: getEnv( 'E2E_NETWORK_ADMIN_PASSWORD', 'AuditAdmin!ChangeThis123' ),
	},
	siteOwner: {
		username: getEnv( 'E2E_SITEOWNER_USERNAME', 'siteowner' ),
		email: getEnv( 'E2E_SITEOWNER_EMAIL', 'siteowner@secaudit.localhost' ),
		password: getEnv( 'E2E_SITEOWNER_PASSWORD', 'SiteOwner!ChangeThis123' ),
	},
	auditor: {
		username: getEnv( 'E2E_AUDITOR_USERNAME', 'auditor' ),
		email: getEnv( 'E2E_AUDITOR_EMAIL', 'auditor@secaudit.localhost' ),
		password: getEnv( 'E2E_AUDITOR_PASSWORD', 'Auditor!ChangeThis123' ),
	},
};

module.exports = env;