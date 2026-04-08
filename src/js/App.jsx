import { useState, useEffect, useCallback } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import ToggleCard from './components/ToggleCard';
import PasskeySection from './components/PasskeySection';
import SamlSettings from './components/SamlSettings';
import OidcSettings from './components/OidcSettings';
import Toast from './components/Toast';

export default function App() {
	const [ tab, setTab ] = useState( 'general' );
	const [ settings, setSettings ] = useState( {
		lockdown_mode: true,
		app_passwords: false,
		role_ceiling: 'editor',
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
					<span className="ea-header__badge">v1.0.0</span>
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
						<PasskeySection showToast={ showToast } />
					</section>
				) }

				{ tab === 'saml' && (
					<SamlSettings showToast={ showToast } />
				) }

				{ tab === 'oidc' && (
					<OidcSettings showToast={ showToast } />
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
