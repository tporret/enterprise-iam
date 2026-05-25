import { useCallback, useEffect, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

function formatDate( value ) {
	if ( ! value ) {
		return 'Never';
	}

	const date = new Date( `${ value }Z` );
	if ( Number.isNaN( date.getTime() ) ) {
		return value;
	}

	return date.toLocaleString();
}

function formatBoolean( value ) {
	if ( value === true ) {
		return 'Yes';
	}

	if ( value === false ) {
		return 'No';
	}

	return 'Unknown';
}

function statusClassName( status ) {
	return status === 'compliant'
		? 'ea-badge ea-badge--active'
		: 'ea-badge ea-badge--inactive';
}

export default function PasskeyCredentialInventory( { showToast, refreshKey = 0 } ) {
	const [ credentials, setCredentials ] = useState( [] );
	const [ loaded, setLoaded ] = useState( false );

	const loadCredentials = useCallback( async () => {
		setLoaded( false );

		try {
			const data = await apiFetch( {
				path: 'enterprise-auth/v1/passkeys/credentials?per_page=100',
			} );

			setCredentials( Array.isArray( data?.items ) ? data.items : [] );
		} catch {
			showToast( 'Failed to load passkey credential inventory.', 'error' );
		} finally {
			setLoaded( true );
		}
	}, [ showToast ] );

	useEffect( () => {
		loadCredentials();
	}, [ loadCredentials, refreshKey ] );

	return (
		<div className="ea-card ea-card--wide">
			<div className="ea-passkey-inventory__header">
				<div>
					<h3 className="ea-card__title">Passkey Credential Inventory</h3>
					<p className="ea-card__desc">
						Review registered passkey provenance, assurance status, and last-use signals for this site.
					</p>
				</div>
				<button
					type="button"
					className="ea-btn ea-btn--sm"
					onClick={ loadCredentials }
					disabled={ ! loaded }
				>
					Refresh
				</button>
			</div>

			{ ! loaded && (
				<p className="ea-card__desc ea-passkey-inventory__empty">Loading passkey inventory&hellip;</p>
			) }

			{ loaded && credentials.length === 0 && (
				<p className="ea-card__desc ea-passkey-inventory__empty">No passkeys are registered for this site yet.</p>
			) }

			{ loaded && credentials.length > 0 && (
				<div className="ea-passkey-inventory__table-wrap">
					<table className="ea-passkey-inventory__table">
						<thead>
							<tr>
								<th>User</th>
								<th>Credential</th>
								<th>Assurance</th>
								<th>Authenticator</th>
								<th>Backup</th>
								<th>Use</th>
							</tr>
						</thead>
						<tbody>
							{ credentials.map( ( credential ) => {
								const userLabel = credential.user?.display_name || credential.user?.login || `User ${ credential.user?.id || 'unknown' }`;
								const transports = Array.isArray( credential.transports ) && credential.transports.length > 0
									? credential.transports.join( ', ' )
									: 'Not reported';

								return (
									<tr key={ credential.id }>
										<td>
											<strong>{ userLabel }</strong>
											<span>{ credential.user?.email || credential.user?.login || 'Unknown account' }</span>
										</td>
										<td>
											<code>{ credential.credential_fingerprint }</code>
											<span>Created { formatDate( credential.created_at ) }</span>
										</td>
										<td>
											<span className={ statusClassName( credential.compliance_status ) }>
												{ credential.compliance_status === 'legacy_non_compliant' ? 'Legacy' : 'Compliant' }
											</span>
											<span>UV initialized: { formatBoolean( credential.uv_initialized ) }</span>
										</td>
										<td>
											<span>{ credential.attestation_type || 'none' }</span>
											<span>{ credential.aaguid || 'No AAGUID' }</span>
											<span>{ transports }</span>
										</td>
										<td>
											<span>Eligible: { formatBoolean( credential.backup_eligible ) }</span>
											<span>Backed up: { formatBoolean( credential.backup_status ) }</span>
										</td>
										<td>
											<span>Last: { formatDate( credential.last_used_at ) }</span>
											<span>Sign count: { credential.sign_count }</span>
											<span>{ credential.registration_origin || 'Unknown origin' }</span>
										</td>
									</tr>
								);
							} ) }
						</tbody>
					</table>
				</div>
			) }
		</div>
	);
}