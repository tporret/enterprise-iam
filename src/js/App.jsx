import { useState, useEffect, useCallback } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import ToggleCard from './components/ToggleCard';
import PasskeySection from './components/PasskeySection';
import SamlSettings from './components/SamlSettings';
import OidcSettings from './components/OidcSettings';
import ScimSettings from './components/ScimSettings';
import Toast from './components/Toast';

export default function App() {
	const [ tab, setTab ] = useState( 'general' );
	const [ settings, setSettings ] = useState( {
		lockdown_mode: true,
		app_passwords: false,
		role_ceiling: 'editor',
		session_timeout: 8,
		deprovision_steward_user_id: 0,
		deprovision_steward_options: [],
		deprovision_steward_user: null,
	} );
	const [ saving, setSaving ] = useState( false );
	const [ loaded, setLoaded ] = useState( false );
	const [ toast, setToast ] = useState( null );

	// Configure apiFetch to use the plugin's nonce.
	useEffect( () => {
		apiFetch.use( apiFetch.createNonceMiddleware( window.enterpriseAuth.nonce ) );

		apiFetch( { path: 'enterprise-auth/v1/settings' } ).then( ( data ) => {
			setSettings( data );
			setLoaded( true );
		} );
	}, [] );

	const showToast = useCallback( ( message, type = 'success' ) => {
		setToast( { message, type } );
	}, [] );

	const updateSetting = ( key, value ) => {
		setSaving( true );
		const updated = { ...settings, [ key ]: value };
		setSettings( updated );

		apiFetch( {
			path: 'enterprise-auth/v1/settings',
			method: 'POST',
			data: updated,
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
					<span className="ea-header__badge">v1.5.2</span>
				</div>
				<p className="ea-header__subtitle">
					Zero Trust security hardening for WordPress
				</p>
			</header>

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

			<main className="ea-main">
				{ tab === 'general' && (
					<section className="ea-card-grid">
						<ToggleCard
							title="Enterprise Lockdown Mode"
							description="Disables XML-RPC, restricts REST API user enumeration, and enforces strict security headers."
							checked={ settings.lockdown_mode }
							disabled={ saving }
							onChange={ ( val ) => updateSetting( 'lockdown_mode', val ) }
						/>
						<ToggleCard
							title="Application Passwords"
							description="Allow non-administrator users to create Application Passwords. When off, only admins may use them."
							checked={ settings.app_passwords }
							disabled={ saving }
							onChange={ ( val ) => updateSetting( 'app_passwords', val ) }
						/>
						<div className="ea-card">
							<h3 className="ea-card__title">SSO Role Ceiling</h3>
							<p className="ea-card__desc">
								Maximum role that SSO / JIT provisioning can assign. Prevents a compromised IdP from granting Administrator access.
							</p>
							<select
								className="ea-input"
								value={ settings.role_ceiling }
								disabled={ saving }
								onChange={ ( e ) => updateSetting( 'role_ceiling', e.target.value ) }
							>
								<option value="editor">Editor</option>
								<option value="author">Author</option>
								<option value="contributor">Contributor</option>
								<option value="subscriber">Subscriber</option>
							</select>
						</div>
						<div className="ea-card">
							<h3 className="ea-card__title">SSO Session Timeout</h3>
							<p className="ea-card__desc">
								Maximum session duration for SSO-authenticated users. After this time, users must re-authenticate with their identity provider.
							</p>
							<select
								className="ea-input"
								value={ settings.session_timeout }
								disabled={ saving }
								onChange={ ( e ) => updateSetting( 'session_timeout', parseInt( e.target.value, 10 ) ) }
							>
								<option value={ 1 }>1 hour</option>
								<option value={ 2 }>2 hours</option>
								<option value={ 4 }>4 hours</option>
								<option value={ 8 }>8 hours</option>
								<option value={ 12 }>12 hours</option>
								<option value={ 24 }>24 hours</option>
							</select>
						</div>
						<PasskeySection showToast={ showToast } />
					</section>
				) }

				{ tab === 'saml' && (
					<SamlSettings showToast={ showToast } />
				) }

				{ tab === 'oidc' && (
					<OidcSettings showToast={ showToast } />
				) }

				{ tab === 'scim' && (
					<ScimSettings
						showToast={ showToast }
						settings={ settings }
						saving={ saving }
						updateSetting={ updateSetting }
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
