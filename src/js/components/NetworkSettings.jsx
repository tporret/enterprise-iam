import { useCallback, useEffect, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import ToggleCard from './ToggleCard';

const DEFAULT_STATE = {
	defaults: {
		lockdown_mode: true,
		app_passwords: false,
		require_device_bound_authenticators: false,
		private_content_login_required: false,
		role_ceiling: 'editor',
		session_timeout: 8,
	},
	policy: {
		allow_site_overrides: {
			lockdown_mode: false,
			app_passwords: false,
			require_device_bound_authenticators: true,
			private_content_login_required: true,
			role_ceiling: false,
			session_timeout: true,
		},
		allow_site_role_mappings: true,
		allow_site_scim: true,
	},
};

function ScopeNote( { children } ) {
	return <p className="ea-scope-meta">{ children }</p>;
}

export default function NetworkSettings( { showToast } ) {
	const [ settings, setSettings ] = useState( DEFAULT_STATE );
	const [ loaded, setLoaded ] = useState( false );
	const [ saving, setSaving ] = useState( false );

	const loadSettings = useCallback( async () => {
		try {
			const data = await apiFetch( { path: 'enterprise-auth/v1/network/defaults' } );
			setSettings( {
				defaults: {
					...DEFAULT_STATE.defaults,
					...( data?.defaults || {} ),
				},
				policy: {
					...DEFAULT_STATE.policy,
					...( data?.policy || {} ),
					allow_site_overrides: {
						...DEFAULT_STATE.policy.allow_site_overrides,
						...( data?.policy?.allow_site_overrides || {} ),
					},
				},
			} );
		} catch {
			showToast( 'Failed to load network defaults.', 'error' );
		} finally {
			setLoaded( true );
		}
	}, [ showToast ] );

	useEffect( () => {
		loadSettings();
	}, [ loadSettings ] );

	const persist = useCallback( async ( nextSettings ) => {
		const previous = settings;
		setSettings( nextSettings );
		setSaving( true );

		try {
			const data = await apiFetch( {
				path: 'enterprise-auth/v1/network/defaults',
				method: 'POST',
				data: nextSettings,
			} );

			setSettings( {
				defaults: {
					...DEFAULT_STATE.defaults,
					...( data?.defaults || {} ),
				},
				policy: {
					...DEFAULT_STATE.policy,
					...( data?.policy || {} ),
					allow_site_overrides: {
						...DEFAULT_STATE.policy.allow_site_overrides,
						...( data?.policy?.allow_site_overrides || {} ),
					},
				},
			} );
			showToast( 'Network defaults saved successfully.' );
		} catch {
			setSettings( previous );
			showToast( 'Failed to save network defaults.', 'error' );
		} finally {
			setSaving( false );
		}
	}, [ settings, showToast ] );

	const updateDefault = useCallback( ( key, value ) => {
		persist( {
			...settings,
			defaults: {
				...settings.defaults,
				[ key ]: value,
			},
		} );
	}, [ persist, settings ] );

	const updateOverridePolicy = useCallback( ( key, value ) => {
		persist( {
			...settings,
			policy: {
				...settings.policy,
				allow_site_overrides: {
					...settings.policy.allow_site_overrides,
					[ key ]: value,
				},
			},
		} );
	}, [ persist, settings ] );

	const updateDelegationPolicy = useCallback( ( key, value ) => {
		persist( {
			...settings,
			policy: {
				...settings.policy,
				[ key ]: value,
			},
		} );
	}, [ persist, settings ] );

	if ( ! loaded ) {
		return <p style={ { color: '#64748b' } }>Loading defaults and policy&hellip;</p>;
	}

	return (
		<div className="ea-card-grid">
			<div className="ea-card ea-card--wide">
				<h3 className="ea-card__title">Defaults and Policy</h3>
				<p className="ea-card__desc">
					Network defaults define the baseline posture for each site. The override policy determines which values site admins may customize locally.
				</p>
			</div>

			<ToggleCard
				title="Enterprise Lockdown Mode"
				description="Disables XML-RPC, restricts REST API user enumeration, and enforces strict security headers."
				checked={ settings.defaults.lockdown_mode }
				disabled={ saving }
				onChange={ ( value ) => updateDefault( 'lockdown_mode', value ) }
				scopeLabel="Network Default"
				scopeTone="network"
				metaDescription={ settings.policy.allow_site_overrides.lockdown_mode ? 'Sites may override this default.' : 'Sites inherit this value and cannot override it.' }
			/>
			<ToggleCard
				title="Require Device-Bound Authenticators"
				description="Reject backup-eligible synced passkeys during enrollment unless a site override is explicitly allowed."
				checked={ settings.defaults.require_device_bound_authenticators }
				disabled={ saving }
				onChange={ ( value ) => updateDefault( 'require_device_bound_authenticators', value ) }
				scopeLabel="Network Default"
				scopeTone="network"
				metaDescription={ settings.policy.allow_site_overrides.require_device_bound_authenticators ? 'Sites may override this default.' : 'Sites inherit this value and cannot override it.' }
			/>
			<ToggleCard
				title="Private Content Login Gate"
				description="Require visitors to authenticate before viewing private posts or pages on this site. Public content remains publicly reachable."
				checked={ settings.defaults.private_content_login_required }
				disabled={ saving }
				onChange={ ( value ) => updateDefault( 'private_content_login_required', value ) }
				scopeLabel="Network Default"
				scopeTone="network"
				metaDescription={ settings.policy.allow_site_overrides.private_content_login_required ? 'Sites may override this default.' : 'Sites inherit this value and cannot override it.' }
			/>
			<ToggleCard
				title="Application Passwords"
				description="Allow non-administrator users to create Application Passwords."
				checked={ settings.defaults.app_passwords }
				disabled={ saving }
				onChange={ ( value ) => updateDefault( 'app_passwords', value ) }
				scopeLabel="Network Default"
				scopeTone="network"
				metaDescription={ settings.policy.allow_site_overrides.app_passwords ? 'Sites may override this default.' : 'Sites inherit this value and cannot override it.' }
			/>

			<div className="ea-card">
				<div className="ea-setting-header">
					<h3 className="ea-card__title">SSO Role Ceiling</h3>
					<span className="ea-scope-tag ea-scope-tag--network">Network Default</span>
				</div>
				<p className="ea-card__desc">
					Maximum role that SSO or JIT provisioning can assign anywhere in the network.
				</p>
				<ScopeNote>
					{ settings.policy.allow_site_overrides.role_ceiling ? 'Sites may override this default.' : 'Sites inherit this value and cannot override it.' }
				</ScopeNote>
				<select
					className="ea-input"
					value={ settings.defaults.role_ceiling }
					disabled={ saving }
					onChange={ ( event ) => updateDefault( 'role_ceiling', event.target.value ) }
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
					<span className="ea-scope-tag ea-scope-tag--network">Network Default</span>
				</div>
				<p className="ea-card__desc">
					Maximum session duration for SSO-authenticated users before re-authentication is required.
				</p>
				<ScopeNote>
					{ settings.policy.allow_site_overrides.session_timeout ? 'Sites may override this default.' : 'Sites inherit this value and cannot override it.' }
				</ScopeNote>
				<select
					className="ea-input"
					value={ settings.defaults.session_timeout }
					disabled={ saving }
					onChange={ ( event ) => updateDefault( 'session_timeout', parseInt( event.target.value, 10 ) ) }
				>
					<option value={ 1 }>1 hour</option>
					<option value={ 2 }>2 hours</option>
					<option value={ 4 }>4 hours</option>
					<option value={ 8 }>8 hours</option>
					<option value={ 12 }>12 hours</option>
					<option value={ 24 }>24 hours</option>
				</select>
			</div>

			<div className="ea-card ea-card--wide">
				<h3 className="ea-card__title">Site Override Policy</h3>
				<p className="ea-card__desc">
					Use these switches to decide which network defaults can be overridden per site.
				</p>
			</div>

			<ToggleCard
				title="Allow Site Override: Enterprise Lockdown Mode"
				description="Permit site admins to override the network lockdown default."
				checked={ settings.policy.allow_site_overrides.lockdown_mode }
				disabled={ saving }
				onChange={ ( value ) => updateOverridePolicy( 'lockdown_mode', value ) }
				scopeLabel="Network Policy"
				scopeTone="policy"
			/>
			<ToggleCard
				title="Allow Site Override: Device-Bound Authenticators"
				description="Permit site admins to relax or strengthen the passkey device-bound requirement."
				checked={ settings.policy.allow_site_overrides.require_device_bound_authenticators }
				disabled={ saving }
				onChange={ ( value ) => updateOverridePolicy( 'require_device_bound_authenticators', value ) }
				scopeLabel="Network Policy"
				scopeTone="policy"
			/>
			<ToggleCard
				title="Allow Site Override: Private Content Login Gate"
				description="Permit site admins to decide whether private posts and pages require login locally."
				checked={ settings.policy.allow_site_overrides.private_content_login_required }
				disabled={ saving }
				onChange={ ( value ) => updateOverridePolicy( 'private_content_login_required', value ) }
				scopeLabel="Network Policy"
				scopeTone="policy"
			/>
			<ToggleCard
				title="Allow Site Override: Application Passwords"
				description="Permit site admins to change the application-password setting locally."
				checked={ settings.policy.allow_site_overrides.app_passwords }
				disabled={ saving }
				onChange={ ( value ) => updateOverridePolicy( 'app_passwords', value ) }
				scopeLabel="Network Policy"
				scopeTone="policy"
			/>
			<ToggleCard
				title="Allow Site Override: Role Ceiling"
				description="Permit site admins to lower or raise the role ceiling within the allowed role set."
				checked={ settings.policy.allow_site_overrides.role_ceiling }
				disabled={ saving }
				onChange={ ( value ) => updateOverridePolicy( 'role_ceiling', value ) }
				scopeLabel="Network Policy"
				scopeTone="policy"
			/>
			<ToggleCard
				title="Allow Site Override: Session Timeout"
				description="Permit site admins to choose a different SSO session timeout for their site."
				checked={ settings.policy.allow_site_overrides.session_timeout }
				disabled={ saving }
				onChange={ ( value ) => updateOverridePolicy( 'session_timeout', value ) }
				scopeLabel="Network Policy"
				scopeTone="policy"
			/>

			<div className="ea-card ea-card--wide">
				<h3 className="ea-card__title">Delegation Policy</h3>
				<p className="ea-card__desc">
					These toggles reserve future site-level delegation paths for role mappings and SCIM behavior.
				</p>
			</div>

			<ToggleCard
				title="Allow Site Role Mappings"
				description="Permit sites to manage role mappings for assigned providers when that capability is introduced."
				checked={ settings.policy.allow_site_role_mappings }
				disabled={ saving }
				onChange={ ( value ) => updateDelegationPolicy( 'allow_site_role_mappings', value ) }
				scopeLabel="Network Policy"
				scopeTone="policy"
			/>
			<ToggleCard
				title="Allow Site SCIM"
				description="Permit sites to own SCIM-related controls when delegated site SCIM support is added."
				checked={ settings.policy.allow_site_scim }
				disabled={ saving }
				onChange={ ( value ) => updateDelegationPolicy( 'allow_site_scim', value ) }
				scopeLabel="Network Policy"
				scopeTone="policy"
			/>
		</div>
	);
}