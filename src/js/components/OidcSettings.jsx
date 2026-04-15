import { useState, useCallback, useEffect } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import AttributeMappingSection from './AttributeMappingSection';
import RoleMappingRow from './RoleMappingRow';
import IdpListCard from './IdpListCard';
import useIdpEditorState, { buildIdpPayload } from './useIdpEditorState';

const OIDC_PROVIDER_OPTIONS = [
	{ value: 'generic', label: 'Generic OIDC' },
	{ value: 'google', label: 'Google' },
	{ value: 'microsoft-entra', label: 'Microsoft Entra ID' },
	{ value: 'okta', label: 'Okta' },
	{ value: 'auth0', label: 'Auth0' },
	{ value: 'ping', label: 'Ping Identity' },
];

const EMPTY_IDP = {
	id: '',
	provider_name: '',
	provider_family: 'generic',
	protocol: 'oidc',
	issuer: '',
	client_id: '',
	client_secret: '',
	authorization_endpoint: '',
	token_endpoint: '',
	userinfo_endpoint: '',
	jwks_uri: '',
	end_session_endpoint: '',
	domain_mapping: [],
	role_mapping: {},
	enabled: true,
	force_reauth: false,
};

export default function OidcSettings( {
	showToast,
	endpointBase = 'enterprise-auth/v1/idps',
	allowMutations = true,
	readOnlyNotice = '',
	showAssignmentCount = false,
	listTitle = 'OIDC Identity Providers',
	addButtonLabel = '+ Add OIDC IdP',
	emptyMessage,
} ) {
	const [ saving, setSaving ] = useState( false );
	const {
		idps,
		loaded,
		editing,
		roleMappings,
		domainText,
		setDomainText,
		loadIdps,
		startEdit,
		startNew,
		cancelEdit,
		updateField,
		updateRoleMapping,
		removeRoleMapping,
		addRoleMapping,
		handleDelete,
	} = useIdpEditorState( {
		endpointBase,
		protocol: 'oidc',
		showToast,
		emptyIdp: EMPTY_IDP,
		onEditorChanged: () => setDiscoveryUrl( '' ),
	} );

	// Discovery auto-fill state.
	const [ discoveryUrl, setDiscoveryUrl ] = useState( '' );
	const [ fetching, setFetching ] = useState( false );

	const startEditOidc = useCallback( ( id ) => {
		startEdit( id, 'Failed to load OIDC configuration.' );
	}, [ startEdit ] );

	// ── Discovery Auto-Fill ─────────────────────────────────────────────

	const handleDiscovery = useCallback( async () => {
		let url = discoveryUrl.trim();
		if ( ! url ) {
			showToast( 'Please enter an Issuer or Discovery URL.', 'error' );
			return;
		}

		// Strip trailing slash before appending the well-known path.
		url = url.replace( /\/+$/, '' );
		if ( ! url.endsWith( '/.well-known/openid-configuration' ) ) {
			url += '/.well-known/openid-configuration';
		}

		setFetching( true );

		try {
			const resp = await window.fetch( url );
			if ( ! resp.ok ) {
				throw new Error( `HTTP ${ resp.status }` );
			}
			const config = await resp.json();

			// Auto-fill the form with discovered values.
			setEditing( ( prev ) => ( {
				...prev,
				issuer: config.issuer || prev.issuer,
				authorization_endpoint:
					config.authorization_endpoint || prev.authorization_endpoint,
				token_endpoint:
					config.token_endpoint || prev.token_endpoint,
				userinfo_endpoint:
					config.userinfo_endpoint || prev.userinfo_endpoint,
				jwks_uri: config.jwks_uri || prev.jwks_uri,
				end_session_endpoint:
					config.end_session_endpoint || prev.end_session_endpoint,
			} ) );

			showToast( 'Discovery successful — fields auto-filled.' );
		} catch {
			showToast(
				'Failed to fetch OpenID Configuration. Check the URL and try again.',
				'error'
			);
		} finally {
			setFetching( false );
		}
	}, [ discoveryUrl, showToast ] );

	// ── Editing helpers ─────────────────────────────────────────────────

	// ── Save ────────────────────────────────────────────────────────────

	const handleSave = useCallback( async () => {
		if ( ! editing ) {
			return;
		}

		setSaving( true );

		const payload = buildIdpPayload( editing, roleMappings, domainText );

		try {
			await apiFetch( {
				path: endpointBase,
				method: 'POST',
				data: payload,
			} );

			showToast( 'OIDC configuration saved successfully.' );
			cancelEdit();
			loadIdps();
		} catch ( error ) {
			showToast(
				error?.message || 'Failed to save OIDC configuration.',
				'error'
			);
		} finally {
			setSaving( false );
		}
	}, [ endpointBase, editing, roleMappings, domainText, showToast, cancelEdit, loadIdps ] );

	if ( ! loaded ) {
		return <p style={ { color: '#64748b' } }>Loading OIDC settings&hellip;</p>;
	}

	// ── Editing form ──────────────────────────────────────────────────

	if ( editing ) {
		return (
			<div className="ea-saml">
				<h2 className="ea-saml__heading">
					{ editing.id
						? 'Edit OIDC Configuration'
						: 'New OIDC Configuration' }
				</h2>

				{ /* Discovery Auto-Fill Tool */ }
				<div className="ea-discovery">
					<div className="ea-discovery__header">
						<span className="ea-discovery__icon">&#x26A1;</span>
						<span className="ea-discovery__title">Quick Setup</span>
					</div>
					<p className="ea-discovery__desc">
						Enter your Issuer URL and we&rsquo;ll auto-fill the
						endpoints via OpenID Discovery.
					</p>
					<div className="ea-discovery__row">
						<input
							type="text"
							className="ea-input ea-discovery__input"
							placeholder="https://dev-1234.okta.com/oauth2/default"
							value={ discoveryUrl }
							onChange={ ( e ) =>
								setDiscoveryUrl( e.target.value )
							}
						/>
						<button
							type="button"
							className="ea-btn ea-btn--primary ea-btn--small"
							disabled={ fetching }
							onClick={ handleDiscovery }
						>
							{ fetching
								? 'Fetching\u2026'
								: 'Fetch Configuration' }
						</button>
					</div>
				</div>

				{ /* Manual Configuration Form */ }
				<div className="ea-form-group">
					<label className="ea-label">Connection Name</label>
					<input
						type="text"
						className="ea-input"
						placeholder="e.g. Corporate Okta"
						value={ editing.provider_name }
						onChange={ ( e ) =>
							updateField( 'provider_name', e.target.value )
						}
					/>
				</div>

				<div className="ea-form-group">
					<label className="ea-label">Provider Type</label>
					<select
						className="ea-input"
						value={ editing.provider_family || 'generic' }
						onChange={ ( e ) =>
							updateField( 'provider_family', e.target.value )
						}
					>
						{ OIDC_PROVIDER_OPTIONS.map( ( option ) => (
							<option key={ option.value } value={ option.value }>
								{ option.label }
							</option>
						) ) }
					</select>
					<p className="ea-label__hint" style={ { margin: '4px 0 0' } }>
						Used for provider-aware setup guidance and attribute mapping presets.
					</p>
				</div>

				<div className="ea-form-group">
					<label className="ea-label">Issuer URL</label>
					<input
						type="text"
						className="ea-input"
						placeholder="https://dev-1234.okta.com/oauth2/default"
						value={ editing.issuer }
						onChange={ ( e ) =>
							updateField( 'issuer', e.target.value )
						}
					/>
				</div>

				<div className="ea-form-group">
					<label className="ea-label">Client ID</label>
					<input
						type="text"
						className="ea-input"
						placeholder="0oa1b2c3d4e5f6g7h8i9"
						value={ editing.client_id }
						onChange={ ( e ) =>
							updateField( 'client_id', e.target.value )
						}
					/>
				</div>

				<div className="ea-form-group">
					<label className="ea-label">Client Secret</label>
					<input
						type="password"
						className="ea-input"
						placeholder="••••••••••••••••"
						value={ editing.client_secret }
						onChange={ ( e ) =>
							updateField( 'client_secret', e.target.value )
						}
					/>
				</div>

				<AttributeMappingSection
					protocol="oidc"
					providerFamily={ editing.provider_family || 'generic' }
					overrideMapping={ editing.override_attribute_mapping || false }
					customEmailAttr={ editing.custom_email_attr || '' }
					customFirstNameAttr={ editing.custom_first_name_attr || '' }
					customLastNameAttr={ editing.custom_last_name_attr || '' }
					onUpdateField={ updateField }
				/>

				<div className="ea-form-group">
					<label className="ea-label">
						Domain Mapping{ ' ' }
						<span className="ea-label__hint">
							(comma-separated, e.g. startup.io, dev.startup.io)
						</span>
					</label>
					<input
						type="text"
						className="ea-input"
						placeholder="startup.io, dev.startup.io"
						value={ domainText }
						onChange={ ( e ) => setDomainText( e.target.value ) }
					/>
				</div>

				<div className="ea-form-group">
					<label className="ea-label">Group to Role Mapping</label>
					{ roleMappings.map( ( rm, idx ) => (
						<RoleMappingRow
							key={ idx }
							group={ rm.group }
							role={ rm.role }
							onChange={ ( field, val ) =>
								updateRoleMapping( idx, field, val )
							}
							onRemove={ () => removeRoleMapping( idx ) }
						/>
					) ) }
					<button
						type="button"
						className="ea-btn ea-btn--secondary ea-btn--small"
						onClick={ addRoleMapping }
					>
						+ Add Mapping
					</button>
				</div>

				<div className="ea-form-group">
					<label className="ea-label">
						<input
							type="checkbox"
							checked={ editing.force_reauth || false }
							onChange={ ( e ) =>
								updateField( 'force_reauth', e.target.checked )
							}
						/>{ ' ' }
						Force Re-Authentication
					</label>
					<p className="ea-label__hint" style={ { margin: '4px 0 0' } }>
						When enabled, the OIDC authorization request includes
						prompt=login, requiring the user to re-authenticate at
						the IdP even if they have an active session.
					</p>
				</div>

				<div className="ea-form-group">
					<label className="ea-label">End Session Endpoint (Logout)</label>
					<input
						type="text"
						className="ea-input"
						placeholder="https://dev-1234.okta.com/oauth2/default/v1/logout"
						value={ editing.end_session_endpoint || '' }
						onChange={ ( e ) =>
							updateField( 'end_session_endpoint', e.target.value )
						}
					/>
					<p className="ea-label__hint" style={ { margin: '4px 0 0' } }>
						When set, WordPress logout will also terminate the IdP
						session (RP-Initiated Logout). Auto-filled by Discovery.
					</p>
				</div>

				<div className="ea-form-actions">
					<button
						type="button"
						className="ea-btn ea-btn--primary"
						disabled={ saving }
						onClick={ handleSave }
					>
						{ saving ? 'Saving\u2026' : 'Save Configuration' }
					</button>
					<button
						type="button"
						className="ea-btn ea-btn--secondary"
						onClick={ cancelEdit }
					>
						Cancel
					</button>
				</div>
			</div>
		);
	}

	// ── List view ─────────────────────────────────────────────────────

	return (
		<div className="ea-saml">
			<IdpListCard
				readOnlyNotice={ readOnlyNotice }
				listTitle={ listTitle }
				allowMutations={ allowMutations }
				addButtonLabel={ addButtonLabel }
				onAdd={ startNew }
				idps={ idps }
				emptyMessage={ emptyMessage }
				emptyFallback={ 'No OIDC providers configured yet. Click "Add OIDC IdP" to set up your first connection.' }
				showAssignmentCount={ showAssignmentCount }
				onEdit={ startEditOidc }
				onDelete={ handleDelete }
			/>
		</div>
	);
}
