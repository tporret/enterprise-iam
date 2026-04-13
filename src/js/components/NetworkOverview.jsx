import { useCallback, useEffect, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

export default function NetworkOverview( { showToast } ) {
	const [ providers, setProviders ] = useState( [] );
	const [ sites, setSites ] = useState( [] );
	const [ loaded, setLoaded ] = useState( false );

	const loadData = useCallback( async () => {
		try {
			const [ networkProviders, networkSites ] = await Promise.all( [
				apiFetch( { path: 'enterprise-auth/v1/network/idps' } ),
				apiFetch( { path: 'enterprise-auth/v1/network/sites' } ),
			] );

			setProviders( Array.isArray( networkProviders ) ? networkProviders : [] );
			setSites( Array.isArray( networkSites ) ? networkSites : [] );
		} catch {
			showToast( 'Failed to load network overview.', 'error' );
		} finally {
			setLoaded( true );
		}
	}, [ showToast ] );

	useEffect( () => {
		loadData();
	}, [ loadData ] );

	if ( ! loaded ) {
		return <p style={ { color: '#64748b' } }>Loading network overview&hellip;</p>;
	}

	const assignedSites = sites.filter( ( site ) => site.assigned_idp_ids?.length > 0 );
	const unassignedSites = sites.filter( ( site ) => ! site.assigned_idp_ids?.length );
	const samlProviders = providers.filter( ( idp ) => idp.protocol === 'saml' );
	const oidcProviders = providers.filter( ( idp ) => idp.protocol === 'oidc' );

	return (
		<div className="ea-network-overview">
			<section className="ea-card-grid ea-card-grid--stats">
				<div className="ea-card ea-stat-card">
					<p className="ea-stat-card__label">Sites</p>
					<p className="ea-stat-card__value">{ sites.length }</p>
				</div>
				<div className="ea-card ea-stat-card">
					<p className="ea-stat-card__label">Assigned Sites</p>
					<p className="ea-stat-card__value">{ assignedSites.length }</p>
				</div>
				<div className="ea-card ea-stat-card">
					<p className="ea-stat-card__label">Network IdPs</p>
					<p className="ea-stat-card__value">{ providers.length }</p>
				</div>
				<div className="ea-card ea-stat-card">
					<p className="ea-stat-card__label">Unassigned Sites</p>
					<p className="ea-stat-card__value">{ unassignedSites.length }</p>
				</div>
			</section>

			<section className="ea-card-grid ea-card-grid--two-up">
				<div className="ea-card">
					<h3 className="ea-card__title">Provider Inventory</h3>
					<p className="ea-card__desc" style={ { marginBottom: 16 } }>
						Network-managed identity providers are defined once and assigned to sites intentionally.
					</p>
					<div className="ea-network-kpis">
						<div className="ea-network-kpi">
							<span className="ea-badge ea-badge--active">SAML</span>
							<strong>{ samlProviders.length }</strong>
						</div>
						<div className="ea-network-kpi">
							<span className="ea-badge ea-badge--active">OIDC</span>
							<strong>{ oidcProviders.length }</strong>
						</div>
					</div>
				</div>

				<div className="ea-card">
					<h3 className="ea-card__title">Sites Missing Assignments</h3>
					{ unassignedSites.length === 0 && (
						<p className="ea-card__desc">Every site currently has at least one assigned identity provider.</p>
					) }
					{ unassignedSites.length > 0 && (
						<ul className="ea-simple-list">
							{ unassignedSites.map( ( site ) => (
								<li key={ site.blog_id }>
									<strong>{ site.name || `Site ${ site.blog_id }` }</strong>
									<span>{ site.url }</span>
								</li>
							) ) }
						</ul>
					) }
				</div>
			</section>
		</div>
	);
}