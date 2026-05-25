import { useCallback, useEffect, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

function scoreTone( score ) {
	if ( score >= 90 ) {
		return 'active';
	}

	if ( score >= 70 ) {
		return 'warning';
	}

	return 'critical';
}

function formatTimestamp( value ) {
	if ( ! value ) {
		return 'Never';
	}

	return new Date( value * 1000 ).toLocaleString();
}

function settingLabel( enabled ) {
	return enabled ? 'On' : 'Off';
}

export default function PostureDashboard( { showToast, network = false } ) {
	const [ posture, setPosture ] = useState( null );
	const [ loaded, setLoaded ] = useState( false );

	const loadPosture = useCallback( async () => {
		setLoaded( false );

		try {
			const data = await apiFetch( {
				path: `enterprise-auth/v1/posture${ network ? '?scope=network' : '' }`,
			} );

			setPosture( data );
		} catch {
			showToast( 'Failed to load IAM posture.', 'error' );
		} finally {
			setLoaded( true );
		}
	}, [ network, showToast ] );

	useEffect( () => {
		loadPosture();
	}, [ loadPosture ] );

	if ( ! loaded ) {
		return <p style={ { color: '#64748b' } }>Loading IAM posture&hellip;</p>;
	}

	if ( ! posture ) {
		return <p className="ea-card__desc">IAM posture is unavailable.</p>;
	}

	if ( network ) {
		return <NetworkPosture posture={ posture } onRefresh={ loadPosture } />;
	}

	return <SitePosture posture={ posture } onRefresh={ loadPosture } />;
}

function Header( { posture, onRefresh, title } ) {
	const tone = scoreTone( posture.score || 0 );

	return (
		<div className="ea-posture-hero">
			<div>
				<p className="ea-posture-hero__eyebrow">IAM Posture</p>
				<h2>{ title }</h2>
			</div>
			<div className={ `ea-posture-score ea-posture-score--${ tone }` }>
				<strong>{ posture.score }</strong>
				<span>Score</span>
			</div>
			<button type="button" className="ea-btn ea-btn--sm" onClick={ onRefresh }>
				Refresh
			</button>
		</div>
	);
}

function SitePosture( { posture, onRefresh } ) {
	const summary = posture.summary || {};
	const users = summary.users || {};
	const sources = summary.identity_sources || {};
	const passkeys = summary.passkeys || {};
	const settings = posture.settings || {};
	const providers = posture.providers || {};

	return (
		<div className="ea-posture-dashboard">
			<Header posture={ posture } onRefresh={ onRefresh } title={ posture.site_name || 'Site posture' } />

			<section className="ea-card-grid ea-card-grid--stats">
				<StatCard label="Users" value={ users.total || 0 } />
				<StatCard label="Enterprise Users" value={ ( sources.sso || 0 ) + ( sources.scim || 0 ) + ( sources.mixed || 0 ) } />
				<StatCard label="Passkeys" value={ passkeys.total || 0 } />
				<StatCard label="Findings" value={ posture.findings?.length || 0 } />
			</section>

			<section className="ea-card-grid ea-card-grid--two-up">
				<div className="ea-card">
					<h3 className="ea-card__title">Identity Coverage</h3>
					<div className="ea-posture-kpi-grid">
						<Kpi label="SSO" value={ sources.sso || 0 } />
						<Kpi label="SCIM" value={ sources.scim || 0 } />
						<Kpi label="Mixed" value={ sources.mixed || 0 } />
						<Kpi label="Local" value={ sources.local || 0 } />
					</div>
					<p className="ea-card__desc ea-posture-spacer">
						Providers: { providers.total || 0 } total, { providers.saml || 0 } SAML, { providers.oidc || 0 } OIDC.
					</p>
				</div>

				<div className="ea-card">
					<h3 className="ea-card__title">Passkey Coverage</h3>
					<div className="ea-posture-kpi-grid">
						<Kpi label="Users Covered" value={ passkeys.users_with_passkeys || 0 } />
						<Kpi label="Missing" value={ passkeys.users_without_passkeys || 0 } />
						<Kpi label="Compliant" value={ passkeys.compliant || 0 } />
						<Kpi label="Legacy" value={ passkeys.legacy_non_compliant || 0 } />
					</div>
					<p className="ea-card__desc ea-posture-spacer">
						Last passkey use: { formatTimestamp( passkeys.latest_last_used_at ) }.
					</p>
				</div>
			</section>

			<section className="ea-card-grid ea-card-grid--two-up">
				<div className="ea-card">
					<h3 className="ea-card__title">Security Controls</h3>
					<div className="ea-posture-settings">
						<Setting label="Lockdown" value={ settingLabel( settings.lockdown_mode ) } active={ settings.lockdown_mode } />
						<Setting label="Device-bound passkeys" value={ settingLabel( settings.require_device_bound_authenticators ) } active={ settings.require_device_bound_authenticators } />
						<Setting label="Private content gate" value={ settingLabel( settings.private_content_login_required ) } active={ settings.private_content_login_required } />
						<Setting label="App passwords" value={ settingLabel( settings.app_passwords ) } active={ ! settings.app_passwords } />
						<Setting label="Role ceiling" value={ settings.role_ceiling || 'Unset' } active={ !! settings.role_ceiling } />
						<Setting label="Session timeout" value={ `${ settings.session_timeout || 0 }h` } active={ !! settings.session_timeout } />
					</div>
				</div>

				<Findings findings={ posture.findings || [] } />
			</section>
		</div>
	);
}

function NetworkPosture( { posture, onRefresh } ) {
	const summary = posture.summary || {};
	const sites = Array.isArray( posture.sites ) ? posture.sites : [];

	return (
		<div className="ea-posture-dashboard">
			<Header posture={ posture } onRefresh={ onRefresh } title="Network posture" />

			<section className="ea-card-grid ea-card-grid--stats">
				<StatCard label="Sites" value={ summary.site_count || 0 } />
				<StatCard label="Needs Attention" value={ summary.sites_needing_attention || 0 } />
				<StatCard label="Users" value={ summary.total_users || 0 } />
				<StatCard label="Step-Up Users" value={ summary.users_requiring_step_up || 0 } />
			</section>

			<div className="ea-card ea-card--wide">
				<h3 className="ea-card__title">Site Risk Rollup</h3>
				<div className="ea-passkey-inventory__table-wrap">
					<table className="ea-passkey-inventory__table ea-posture-sites__table">
						<thead>
							<tr>
								<th>Site</th>
								<th>Score</th>
								<th>Users</th>
								<th>Local</th>
								<th>Legacy Passkeys</th>
								<th>Assignments</th>
								<th>Findings</th>
							</tr>
						</thead>
						<tbody>
							{ sites.map( ( site ) => (
								<tr key={ site.blog_id }>
									<td>
										<strong>{ site.name || `Site ${ site.blog_id }` }</strong>
										<span>{ site.url }</span>
									</td>
									<td><span className={ `ea-badge ea-badge--${ scoreTone( site.score ) }` }>{ site.score }</span></td>
									<td>{ site.user_count }</td>
									<td>{ site.local_users }</td>
									<td>{ site.legacy_passkeys }</td>
									<td>{ site.assigned_provider_count }</td>
									<td>{ site.finding_count }</td>
								</tr>
							) ) }
						</tbody>
					</table>
				</div>
			</div>
		</div>
	);
}

function StatCard( { label, value } ) {
	return (
		<div className="ea-card ea-stat-card">
			<p className="ea-stat-card__label">{ label }</p>
			<p className="ea-stat-card__value">{ value }</p>
		</div>
	);
}

function Kpi( { label, value } ) {
	return (
		<div className="ea-network-kpi">
			<span className="ea-badge ea-badge--active">{ label }</span>
			<strong>{ value }</strong>
		</div>
	);
}

function Setting( { label, value, active } ) {
	return (
		<div className="ea-posture-setting">
			<span>{ label }</span>
			<strong className={ `ea-badge ${ active ? 'ea-badge--active' : 'ea-badge--inactive' }` }>{ value }</strong>
		</div>
	);
}

function Findings( { findings } ) {
	return (
		<div className="ea-card">
			<h3 className="ea-card__title">Findings</h3>
			{ findings.length === 0 && (
				<p className="ea-card__desc">No posture findings detected.</p>
			) }
			{ findings.length > 0 && (
				<ul className="ea-simple-list ea-posture-findings">
					{ findings.map( ( finding ) => (
						<li key={ finding.code }>
							<span className={ `ea-badge ea-badge--${ finding.severity === 'critical' ? 'critical' : finding.severity === 'warning' ? 'warning' : 'inactive' }` }>
								{ finding.severity }
							</span>
							<strong>{ finding.message }</strong>
						</li>
					) ) }
				</ul>
			) }
		</div>
	);
}
