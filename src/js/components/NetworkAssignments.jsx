import { useCallback, useEffect, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

function buildAssignedProviders( assignedIds, providers ) {
	return providers
		.filter( ( provider ) => assignedIds.includes( provider.id ) )
		.map( ( provider ) => ( {
			id: provider.id,
			provider_name: provider.provider_name,
			protocol: provider.protocol,
		} ) );
}

export default function NetworkAssignments( { showToast } ) {
	const [ providers, setProviders ] = useState( [] );
	const [ sites, setSites ] = useState( [] );
	const [ loaded, setLoaded ] = useState( false );
	const [ savingBlogId, setSavingBlogId ] = useState( 0 );

	const loadData = useCallback( async () => {
		try {
			const [ networkProviders, networkSites ] = await Promise.all( [
				apiFetch( { path: 'enterprise-auth/v1/network/idps' } ),
				apiFetch( { path: 'enterprise-auth/v1/network/sites' } ),
			] );

			setProviders( Array.isArray( networkProviders ) ? networkProviders : [] );
			setSites( Array.isArray( networkSites ) ? networkSites : [] );
		} catch {
			showToast( 'Failed to load site assignments.', 'error' );
		} finally {
			setLoaded( true );
		}
	}, [ showToast ] );

	useEffect( () => {
		loadData();
	}, [ loadData ] );

	const updateSiteDraft = useCallback( ( blogId, updater ) => {
		setSites( ( current ) =>
			current.map( ( site ) =>
				site.blog_id === blogId ? updater( site ) : site
			)
		);
	}, [] );

	const toggleProvider = useCallback( ( blogId, providerId, checked ) => {
		updateSiteDraft( blogId, ( site ) => {
			const assigned = checked
				? [ ...site.assigned_idp_ids, providerId ]
				: site.assigned_idp_ids.filter( ( id ) => id !== providerId );

			const assignedUnique = [ ...new Set( assigned ) ];
			const primaryId = assignedUnique.includes( site.primary_idp_id )
				? site.primary_idp_id
				: assignedUnique[ 0 ] || '';

			return {
				...site,
				assigned_idp_ids: assignedUnique,
				primary_idp_id: primaryId,
				assigned_idps: buildAssignedProviders( assignedUnique, providers ),
			};
		} );
	}, [ providers, updateSiteDraft ] );

	const saveAssignments = useCallback( async ( blogId ) => {
		const site = sites.find( ( entry ) => entry.blog_id === blogId );
		if ( ! site ) {
			return;
		}

		setSavingBlogId( blogId );

		try {
			const response = await apiFetch( {
				path: `enterprise-auth/v1/network/sites/${ blogId }/assignments`,
				method: 'POST',
				data: {
					assigned_idp_ids: site.assigned_idp_ids,
					primary_idp_id: site.primary_idp_id,
				},
			} );

			updateSiteDraft( blogId, ( current ) => ( {
				...current,
				...response,
				assigned_idps: buildAssignedProviders( response.assigned_idp_ids || [], providers ),
			} ) );
			showToast( 'Site assignments saved successfully.' );
		} catch {
			showToast( 'Failed to save site assignments.', 'error' );
		} finally {
			setSavingBlogId( 0 );
		}
	}, [ providers, showToast, sites, updateSiteDraft ] );

	if ( ! loaded ) {
		return <p style={ { color: '#64748b' } }>Loading site assignments&hellip;</p>;
	}

	if ( providers.length === 0 ) {
		return (
			<div className="ea-card">
				<h3 className="ea-card__title">Site Assignments</h3>
				<p className="ea-card__desc">
					Add one or more network identity providers before assigning them to sites.
				</p>
			</div>
		);
	}

	return (
		<div className="ea-assignments">
			<div className="ea-card" style={ { marginBottom: 20 } }>
				<h3 className="ea-card__title">Assignment Model</h3>
				<p className="ea-card__desc">
					Each site uses an explicit subset of network-managed providers. The primary provider is the default operational choice for that site.
				</p>
			</div>

			<div className="ea-card-grid">
				{ sites.map( ( site ) => (
					<div className="ea-card ea-assignment-card" key={ site.blog_id }>
						<div className="ea-assignment-card__header">
							<div>
								<h3 className="ea-card__title" style={ { marginBottom: 4 } }>
									{ site.name || `Site ${ site.blog_id }` }
								</h3>
								<p className="ea-card__desc">{ site.url }</p>
							</div>
							<a className="ea-link" href={ site.dashboard_url }>
								Open Site Dashboard
							</a>
						</div>

						<div className="ea-assignment-card__providers">
							{ providers.map( ( provider ) => {
								const checked = site.assigned_idp_ids.includes( provider.id );

								return (
									<label className="ea-provider-check" key={ provider.id }>
										<input
											type="checkbox"
											checked={ checked }
											onChange={ ( event ) =>
												toggleProvider( site.blog_id, provider.id, event.target.checked )
											}
										/>
										<span className="ea-provider-check__label">
											<strong>{ provider.provider_name || '(Untitled)' }</strong>
											<span>{ provider.protocol.toUpperCase() }</span>
										</span>
									</label>
								);
							} ) }
						</div>

						<div className="ea-form-group" style={ { marginBottom: 0 } }>
							<label className="ea-label">Primary Provider</label>
							<select
								className="ea-input"
								value={ site.primary_idp_id || '' }
								disabled={ site.assigned_idp_ids.length === 0 }
								onChange={ ( event ) =>
									updateSiteDraft( site.blog_id, ( current ) => ( {
										...current,
										primary_idp_id: event.target.value,
									} ) )
								}
							>
								<option value="">No primary provider selected</option>
								{ providers
									.filter( ( provider ) => site.assigned_idp_ids.includes( provider.id ) )
									.map( ( provider ) => (
										<option key={ provider.id } value={ provider.id }>
											{ provider.provider_name || '(Untitled)' }
										</option>
									) ) }
							</select>
						</div>

						<div className="ea-form-actions">
							<button
								type="button"
								className="ea-btn ea-btn--primary"
								disabled={ savingBlogId === site.blog_id }
								onClick={ () => saveAssignments( site.blog_id ) }
							>
								{ savingBlogId === site.blog_id ? 'Saving...' : 'Save Assignments' }
							</button>
						</div>
					</div>
				) ) }
			</div>
		</div>
	);
}