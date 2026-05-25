import { useCallback, useEffect, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

function formatDate( value ) {
	if ( ! value ) {
		return 'Unknown';
	}

	const date = new Date( `${ value }Z` );
	if ( Number.isNaN( date.getTime() ) ) {
		return value;
	}

	return date.toLocaleString();
}

function eventLabel( event ) {
	return String( event || '' ).replace( /_/g, ' ' );
}

function actorLabel( event ) {
	if ( event.actor_user_id ) {
		return `User ${ event.actor_user_id }`;
	}

	return event.source === 'scim' ? 'SCIM client' : 'System';
}

export default function AuditEvents( { showToast } ) {
	const [ events, setEvents ] = useState( [] );
	const [ loaded, setLoaded ] = useState( false );

	const loadEvents = useCallback( async () => {
		setLoaded( false );

		try {
			const data = await apiFetch( {
				path: 'enterprise-auth/v1/audit-events?per_page=100',
			} );

			setEvents( Array.isArray( data?.items ) ? data.items : [] );
		} catch {
			showToast( 'Failed to load audit events.', 'error' );
		} finally {
			setLoaded( true );
		}
	}, [ showToast ] );

	useEffect( () => {
		loadEvents();
	}, [ loadEvents ] );

	return (
		<div className="ea-card ea-card--wide">
			<div className="ea-passkey-inventory__header">
				<div>
					<h3 className="ea-card__title">Audit Log</h3>
					<p className="ea-card__desc">
						Review recent IAM security events, configuration changes, and passkey step-up outcomes.
					</p>
				</div>
				<button
					type="button"
					className="ea-btn ea-btn--sm"
					onClick={ loadEvents }
					disabled={ ! loaded }
				>
					Refresh
				</button>
			</div>

			{ ! loaded && (
				<p className="ea-card__desc ea-passkey-inventory__empty">Loading audit events&hellip;</p>
			) }

			{ loaded && events.length === 0 && (
				<p className="ea-card__desc ea-passkey-inventory__empty">No audit events have been recorded yet.</p>
			) }

			{ loaded && events.length > 0 && (
				<div className="ea-passkey-inventory__table-wrap">
					<table className="ea-passkey-inventory__table ea-audit-events__table">
						<thead>
							<tr>
								<th>Time</th>
								<th>Event</th>
								<th>Actor</th>
								<th>Request</th>
								<th>Result</th>
							</tr>
						</thead>
						<tbody>
							{ events.map( ( event ) => (
								<tr key={ event.id }>
									<td>{ formatDate( event.created_at ) }</td>
									<td>
										<strong>{ eventLabel( event.event ) }</strong>
										<span>{ event.source || 'system' }</span>
									</td>
									<td>
										<span>{ actorLabel( event ) }</span>
										{ event.target_user_id && <span>Target user { event.target_user_id }</span> }
									</td>
									<td>
										<span>{ event.request_method || 'N/A' }</span>
										<span>{ event.request_route || 'No route' }</span>
									</td>
									<td>
										<span className={ `ea-badge ${ event.result === 'success' ? 'ea-badge--active' : 'ea-badge--inactive' }` }>
											{ event.result || 'success' }
										</span>
										{ event.metadata?.reason && <span>{ event.metadata.reason }</span> }
									</td>
								</tr>
							) ) }
						</tbody>
					</table>
				</div>
			) }
		</div>
	);
}