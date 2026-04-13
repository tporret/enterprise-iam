import { useState, useEffect, useCallback } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import ToggleCard from './components/ToggleCard';
import PasskeySection from './components/PasskeySection';
import NetworkAssignments from './components/NetworkAssignments';
import NetworkOverview from './components/NetworkOverview';
import NetworkSettings from './components/NetworkSettings';
import SamlSettings from './components/SamlSettings';
import OidcSettings from './components/OidcSettings';
import ScimSettings from './components/ScimSettings';
import Toast from './components/Toast';

export default function App() {
	const screen = window.enterpriseAuth?.screen || 'settings';
	const isNetworkAdmin = !! window.enterpriseAuth?.isNetworkAdmin;
	const isNetworkManagedSite = !! window.enterpriseAuth?.isNetworkManagedSite;
	const isNetworkScreen = isNetworkAdmin && screen.startsWith( 'network-' );
	const initialTab = isNetworkScreen
		? ( screen === 'network-idps'
			? 'providers'
			: screen === 'network-assignments'
				? 'assignments'
				: screen === 'network-policy'
					? 'policy'
				: 'overview' )
		: 'general';

	const [ tab, setTab ] = useState( initialTab );
	const [ providerTab, setProviderTab ] = useState( 'saml' );
	const [ settings, setSettings ] = useState( {
		lockdown_mode: true,
		app_passwords: false,
		require_device_bound_authenticators: false,
		role_ceiling: 'editor',
		session_timeout: 8,
		deprovision_steward_user_id: 0,
		deprovision_steward_options: [],
		scope_meta: {},
	} );
	const [ saving, setSaving ] = useState( false );
	const [ loaded, setLoaded ] = useState( false );
	const [ toast, setToast ] = useState( null );

	useEffect( () => {
		apiFetch.use( apiFetch.createNonceMiddleware( window.enterpriseAuth.nonce ) );

		if ( isNetworkScreen ) {
			setLoaded( true );
			return;
		}

		apiFetch( { path: 'enterprise-auth/v1/settings' } ).then( ( data ) => {
			setSettings( data );
			setLoaded( true );
		} );
	}, [ isNetworkScreen ] );

	const showToast = useCallback( ( message, type = 'success' ) => {
		setToast( { message, type } );
	}, [] );

	const scopeMeta = settings.scope_meta || {};
	const getScopeMeta = useCallback( ( key ) => scopeMeta?.[ key ] || null, [ scopeMeta ] );

	const renderScopeTag = useCallback( ( key ) => {
		const scope = getScopeMeta( key );
		if ( ! scope?.label ) {
			return null;
		}

		return (
			<span className={ `ea-scope-tag ea-scope-tag--${ scope.tone || 'site-only' }` }>
				{ scope.label }
			</span>
		);
	}, [ getScopeMeta ] );

	const updateSetting = ( key, value ) => {
		setSaving( true );
		const updated = { ...settings, [ key ]: value };
		setSettings( updated );

		apiFetch( {
			path: 'enterprise-auth/v1/settings',
			method: 'POST',
			data: { [ key ]: value },
		} ).then( ( data ) => {
			setSettings( data );
			setSaving( false );
			showToast( 'Settings saved successfully.' );
		} ).catch( () => {
			setSaving( false );
			showToast( 'Failed to save settings.', 'error' );
		} );
	};

	if ( ! loaded ) {
		return (
			<div className="ea-loading">
				<p>Loading Enterprise Auth&hellip;</p>
			</div>
		);
	}

	return (
		<div className="ea-wrap">
			<header className="ea-header">
				<div className="ea-header__inner">
					<h1 className="ea-header__title">Enterprise Auth</h1>
					<span className="ea-header__badge">v1.5.3</span>
				</div>
				<p className="ea-header__subtitle">
					{ isNetworkScreen
						? 'Network control plane for multisite identity and access management'
						: 'Zero Trust security hardening for WordPress' }
				</p>
			</header>

			{ isNetworkScreen ? (
				<nav className="ea-tabs">
					<button
						type="button"
						className={ `ea-tabs__btn${ tab === 'overview' ? ' ea-tabs__btn--active' : '' }` }
						onClick={ () => setTab( 'overview' ) }
					>
						Overview
					</button>
					<button
						type="button"
						className={ `ea-tabs__btn${ tab === 'providers' ? ' ea-tabs__btn--active' : '' }` }
						onClick={ () => setTab( 'providers' ) }
					>
						Identity Providers
					</button>
					<button
						type="button"
						className={ `ea-tabs__btn${ tab === 'assignments' ? ' ea-tabs__btn--active' : '' }` }
						onClick={ () => setTab( 'assignments' ) }
					>
						Site Assignments
					</button>
					<button
						type="button"
						className={ `ea-tabs__btn${ tab === 'policy' ? ' ea-tabs__btn--active' : '' }` }
						onClick={ () => setTab( 'policy' ) }
					>
						Defaults &amp; Policy
					</button>
				</nav>
			) : (
				<nav className="ea-tabs">
					<button
						type="button"
						className={ `ea-tabs__btn${ tab === 'general' ? ' ea-tabs__btn--active' : '' }` }
						onClick={ () => setTab( 'general' ) }
					>
						General &amp; Passkeys
					</button>
					<button
						type="button"
						className={ `ea-tabs__btn${ tab === 'saml' ? ' ea-tabs__btn--active' : '' }` }
						onClick={ () => setTab( 'saml' ) }
					>
						Enterprise SSO (SAML)
					</button>
					<button
						type="button"
						className={ `ea-tabs__btn${ tab === 'oidc' ? ' ea-tabs__btn--active' : '' }` }
						onClick={ () => setTab( 'oidc' ) }
					>
						Enterprise SSO (OIDC)
					</button>
					<button
						type="button"
						className={ `ea-tabs__btn${ tab === 'scim' ? ' ea-tabs__btn--active' : '' }` }
						onClick={ () => setTab( 'scim' ) }
					>
						SCIM Provisioning
					</button>
				</nav>
			) }

			<main className="ea-main">
				{ ! isNetworkScreen && isNetworkManagedSite && (
					<div className="ea-scope-banner">
						<strong>Managed by Network Admin.</strong>{ ' ' }
						Identity providers for this site are assigned from Network Admin. This site can review assigned providers while the rest of the dashboard keeps its current layout for this release.
					</div>
				) }

				{ isNetworkScreen && tab === 'overview' && (
					<NetworkOverview showToast={ showToast } />
				) }

				{ isNetworkScreen && tab === 'providers' && (
					<>
						<nav className="ea-subtabs">
							<button
								type="button"
								className={ `ea-subtabs__btn${ providerTab === 'saml' ? ' ea-subtabs__btn--active' : '' }` }
								onClick={ () => setProviderTab( 'saml' ) }
							>
								SAML
							</button>
							<button
								type="button"
								className={ `ea-subtabs__btn${ providerTab === 'oidc' ? ' ea-subtabs__btn--active' : '' }` }
								onClick={ () => setProviderTab( 'oidc' ) }
							>
								OIDC
							</button>
						</nav>

						{ providerTab === 'saml' && (
							<SamlSettings
								showToast={ showToast }
								endpointBase="enterprise-auth/v1/network/idps"
								allowMutations={ true }
								showAssignmentCount={ true }
								listTitle="SAML Identity Providers"
								addButtonLabel="+ Add SAML IdP"
								emptyMessage="No SAML identity providers configured yet. Add one here, then assign it to sites."
							/>
						) }

						{ providerTab === 'oidc' && (
							<OidcSettings
								showToast={ showToast }
								endpointBase="enterprise-auth/v1/network/idps"
								allowMutations={ true }
								showAssignmentCount={ true }
								listTitle="OIDC Identity Providers"
								addButtonLabel="+ Add OIDC IdP"
								emptyMessage="No OIDC identity providers configured yet. Add one here, then assign it to sites."
							/>
						) }
					</>
				) }

				{ isNetworkScreen && tab === 'assignments' && (
					<NetworkAssignments showToast={ showToast } />
				) }

				{ isNetworkScreen && tab === 'policy' && (
					<NetworkSettings showToast={ showToast } />
				) }

				{ ! isNetworkScreen && tab === 'general' && (
					<section className="ea-card-grid">
						<ToggleCard
							title="Enterprise Lockdown Mode"
							description="Disables XML-RPC, restricts REST API user enumeration, and enforces strict security headers."
							checked={ settings.lockdown_mode }
							disabled={ saving || getScopeMeta( 'lockdown_mode' )?.editable === false }
							onChange={ ( val ) => updateSetting( 'lockdown_mode', val ) }
							scopeLabel={ getScopeMeta( 'lockdown_mode' )?.label || '' }
							scopeTone={ getScopeMeta( 'lockdown_mode' )?.tone || 'site-only' }
							metaDescription={ getScopeMeta( 'lockdown_mode' )?.description || '' }
						/>
						<ToggleCard
							title="Require Device-Bound Authenticators"
							description="Reject backup-eligible synced passkeys during enrollment. Launch support is Safari-first on managed Apple devices and other approved platform authenticators. Existing non-compliant passkeys enter a controlled step-up migration path when this is enabled."
							checked={ settings.require_device_bound_authenticators }
							disabled={ saving || getScopeMeta( 'require_device_bound_authenticators' )?.editable === false }
							onChange={ ( val ) => updateSetting( 'require_device_bound_authenticators', val ) }
							scopeLabel={ getScopeMeta( 'require_device_bound_authenticators' )?.label || '' }
							scopeTone={ getScopeMeta( 'require_device_bound_authenticators' )?.tone || 'site-only' }
							metaDescription={ getScopeMeta( 'require_device_bound_authenticators' )?.description || '' }
						/>
						<ToggleCard
							title="Application Passwords"
							description="Allow non-administrator users to create Application Passwords. When off, only admins may use them."
							checked={ settings.app_passwords }
							disabled={ saving || getScopeMeta( 'app_passwords' )?.editable === false }
							onChange={ ( val ) => updateSetting( 'app_passwords', val ) }
							scopeLabel={ getScopeMeta( 'app_passwords' )?.label || '' }
							scopeTone={ getScopeMeta( 'app_passwords' )?.tone || 'site-only' }
							metaDescription={ getScopeMeta( 'app_passwords' )?.description || '' }
						/>
						<div className="ea-card">
							<div className="ea-setting-header">
								<h3 className="ea-card__title">SSO Role Ceiling</h3>
								{ renderScopeTag( 'role_ceiling' ) }
							</div>
							<p className="ea-card__desc">
								Maximum role that SSO / JIT provisioning can assign. Prevents a compromised IdP from granting Administrator access.
							</p>
							{ getScopeMeta( 'role_ceiling' )?.description && (
								<p className="ea-scope-meta">{ getScopeMeta( 'role_ceiling' ).description }</p>
							) }
							<select
								className="ea-input"
								value={ settings.role_ceiling }
								disabled={ saving || getScopeMeta( 'role_ceiling' )?.editable === false }
								onChange={ ( event ) => updateSetting( 'role_ceiling', event.target.value ) }
							>
								<option value="editor">Editor</option>
								<option value="author">Author</option>
								<option value="contributor">Contributor</option>
								<option value="subscriber">Subscriber</option>
							</select>
						</div>
						<div className="ea-card">
							<div className="ea-setting-header">
								<h3 className="ea-card__title">SSO Session Timeout</h3>
								{ renderScopeTag( 'session_timeout' ) }
							</div>
							<p className="ea-card__desc">
								Maximum session duration for SSO-authenticated users. After this time, users must re-authenticate with their identity provider.
							</p>
							{ getScopeMeta( 'session_timeout' )?.description && (
								<p className="ea-scope-meta">{ getScopeMeta( 'session_timeout' ).description }</p>
							) }
							<select
								className="ea-input"
								value={ settings.session_timeout }
								disabled={ saving || getScopeMeta( 'session_timeout' )?.editable === false }
								onChange={ ( event ) => updateSetting( 'session_timeout', parseInt( event.target.value, 10 ) ) }
							>
								<option value={ 1 }>1 hour</option>
								<option value={ 2 }>2 hours</option>
								<option value={ 4 }>4 hours</option>
								<option value={ 8 }>8 hours</option>
								<option value={ 12 }>12 hours</option>
								<option value={ 24 }>24 hours</option>
							</select>
						</div>
						<PasskeySection
							showToast={ showToast }
							requireDeviceBound={ settings.require_device_bound_authenticators }
						/>
					</section>
				) }

				{ ! isNetworkScreen && tab === 'saml' && (
					<SamlSettings
						showToast={ showToast }
						allowMutations={ ! isNetworkManagedSite }
						readOnlyNotice={ isNetworkManagedSite ? 'Assigned SAML providers are managed by Network Admin for this site.' : '' }
						emptyMessage={ isNetworkManagedSite ? 'No SAML identity providers are assigned to this site yet.' : undefined }
					/>
				) }

				{ ! isNetworkScreen && tab === 'oidc' && (
					<OidcSettings
						showToast={ showToast }
						allowMutations={ ! isNetworkManagedSite }
						readOnlyNotice={ isNetworkManagedSite ? 'Assigned OIDC providers are managed by Network Admin for this site.' : '' }
						emptyMessage={ isNetworkManagedSite ? 'No OIDC identity providers are assigned to this site yet.' : undefined }
					/>
				) }

				{ ! isNetworkScreen && tab === 'scim' && (
					<ScimSettings
						showToast={ showToast }
						settings={ settings }
						saving={ saving }
						updateSetting={ updateSetting }
						scopeMeta={ getScopeMeta( 'deprovision_steward_user_id' ) }
					/>
				) }
			</main>

			{ toast && (
				<Toast
					message={ toast.message }
					type={ toast.type }
					onDismiss={ () => setToast( null ) }
				/>
			) }
		</div>
	);
}
