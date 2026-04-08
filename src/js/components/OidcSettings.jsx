import { useState, useCallback } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import AttributeMappingSection from './AttributeMappingSection';

const WP_ROLES = [
	{ value: 'editor', label: 'Editor' },
	{ value: 'author', label: 'Author' },
	{ value: 'contributor', label: 'Contributor' },
	{ value: 'subscriber', label: 'Subscriber' },
];

const EMPTY_IDP = {
	id: '',
	provider_name: '',
	protocol: 'oidc',
	issuer: '',
	client_id: '',
	client_secret: '',
	authorization_endpoint: '',
	token_endpoint: '',
	userinfo_endpoint: '',
	jwks_uri: '',
	domain_mapping: [],
	role_mapping: {},
	enabled: true,
	force_reauth: false,
};

function RoleMappingRow( { group, role, onChange, onRemove } ) {
	return (
		<div className="ea-role-row">
			<input
				type="text"
				className="ea-input ea-role-row__group"
				placeholder="IdP Group Name"
				value={ group }
				onChange={ ( e ) => onChange( 'group', e.target.value ) }
			/>
			<select
				className="ea-input ea-role-row__role"
				value={ role }
				onChange={ ( e ) => onChange( 'role', e.target.value ) }
			>
				{ WP_ROLES.map( ( r ) => (
					<option key={ r.value } value={ r.value }>
						{ r.label }
					</option>
				) ) }
			</select>
			<button
				type="button"
				className="ea-btn ea-btn--danger ea-btn--small"
				onClick={ onRemove }
			>
				&times;
			</button>
		</div>
	);
}

export default function OidcSettings( { showToast } ) {
	const [ idps, setIdps ] = useState( [] );
	const [ loaded, setLoaded ] = useState( false );
	const [ editing, setEditing ] = useState( null );
	const [ saving, setSaving ] = useState( false );
	const [ roleMappings, setRoleMappings ] = useState( [] );
	const [ domainText, setDomainText ] = useState( '' );

	// Discovery auto-fill state.
	const [ discoveryUrl, setDiscoveryUrl ] = useState( '' );
	const [ fetching, setFetching ] = useState( false );

	// Load IdPs on mount (filter to OIDC only for display).
	const loadIdps = useCallback( () => {
		apiFetch( { path: 'enterprise-auth/v1/idps' } )
			.then( ( data ) => {
				const all = Array.isArray( data ) ? data : [];
				setIdps( all.filter( ( idp ) => idp.protocol === 'oidc' ) );
				setLoaded( true );
			} )
			.catch( () => {
				setLoaded( true );
			} );
	}, [] );

	// Run once on mount.
	useState( () => {
		loadIdps();
	} );

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

	const startEdit = useCallback( ( idp ) => {
		const mapped = Object.entries( idp.role_mapping || {} ).map(
			( [ group, role ] ) => ( { group, role } )
		);
		setEditing( { ...idp } );
		setRoleMappings(
			mapped.length > 0 ? mapped : [ { group: '', role: 'subscriber' } ]
		);
		setDomainText( ( idp.domain_mapping || [] ).join( ', ' ) );
		setDiscoveryUrl( '' );
	}, [] );

	const startNew = useCallback( () => {
		startEdit( { ...EMPTY_IDP } );
	}, [ startEdit ] );

	const cancelEdit = useCallback( () => {
		setEditing( null );
		setRoleMappings( [] );
		setDomainText( '' );
		setDiscoveryUrl( '' );
	}, [] );

	const updateField = useCallback( ( key, value ) => {
		setEditing( ( prev ) => ( { ...prev, [ key ]: value } ) );
	}, [] );

	const updateRoleMapping = useCallback( ( idx, field, value ) => {
		setRoleMappings( ( prev ) => {
			const next = [ ...prev ];
			next[ idx ] = { ...next[ idx ], [ field ]: value };
			return next;
		} );
	}, [] );

	const removeRoleMapping = useCallback( ( idx ) => {
		setRoleMappings( ( prev ) => prev.filter( ( _, i ) => i !== idx ) );
	}, [] );

	const addRoleMapping = useCallback( () => {
		setRoleMappings( ( prev ) => [
			...prev,
			{ group: '', role: 'subscriber' },
		] );
	}, [] );

	// ── Save ────────────────────────────────────────────────────────────

	const handleSave = useCallback( async () => {
		if ( ! editing ) {
			return;
		}

		setSaving( true );

		const role_mapping = {};
		roleMappings.forEach( ( { group, role } ) => {
			const g = group.trim();
			if ( g ) {
				role_mapping[ g ] = role;
			}
		} );

		const domain_mapping = domainText
			.split( ',' )
			.map( ( d ) => d.trim().toLowerCase() )
			.filter( Boolean );

		const payload = {
			...editing,
			role_mapping,
			domain_mapping,
		};

		try {
			await apiFetch( {
				path: 'enterprise-auth/v1/idps',
				method: 'POST',
				data: payload,
			} );

			showToast( 'OIDC configuration saved successfully.' );
			cancelEdit();
			loadIdps();
		} catch {
			showToast( 'Failed to save OIDC configuration.', 'error' );
		} finally {
			setSaving( false );
		}
	}, [ editing, roleMappings, domainText, showToast, cancelEdit, loadIdps ] );

	// ── Delete ──────────────────────────────────────────────────────────

	const handleDelete = useCallback(
		async ( id ) => {
			try {
				await apiFetch( {
					path: `enterprise-auth/v1/idps/${ id }`,
					method: 'DELETE',
				} );
				showToast( 'IdP deleted.' );
				loadIdps();
			} catch {
				showToast( 'Failed to delete IdP.', 'error' );
			}
		},
		[ showToast, loadIdps ]
	);

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
			<div className="ea-card">
				<div
					className="ea-card__body"
					style={ {
						justifyContent: 'space-between',
						alignItems: 'center',
					} }
				>
					<h3 className="ea-card__title" style={ { margin: 0 } }>
						OIDC Identity Providers
					</h3>
					<button
						type="button"
						className="ea-btn ea-btn--primary ea-btn--small"
						onClick={ startNew }
					>
						+ Add OIDC IdP
					</button>
				</div>

				{ idps.length === 0 && (
					<p
						className="ea-card__desc"
						style={ { marginTop: 12 } }
					>
						No OIDC providers configured yet. Click &ldquo;Add
						OIDC IdP&rdquo; to set up your first connection.
					</p>
				) }

				{ idps.length > 0 && (
					<table className="ea-idp-table">
						<thead>
							<tr>
								<th>Name</th>
								<th>Domains</th>
								<th>Status</th>
								<th>Actions</th>
							</tr>
						</thead>
						<tbody>
							{ idps.map( ( idp ) => (
								<tr key={ idp.id }>
									<td>
										{ idp.provider_name || '(Untitled)' }
									</td>
									<td>
										{ ( idp.domain_mapping || [] ).join(
											', '
										) || '\u2014' }
									</td>
									<td>
										<span
											className={ `ea-badge ${
												idp.enabled
													? 'ea-badge--active'
													: 'ea-badge--inactive'
											}` }
										>
											{ idp.enabled
												? 'Active'
												: 'Inactive' }
										</span>
									</td>
									<td>
										<button
											type="button"
											className="ea-btn ea-btn--secondary ea-btn--small"
											onClick={ () =>
												startEdit( idp )
											}
										>
											Edit
										</button>{ ' ' }
										<button
											type="button"
											className="ea-btn ea-btn--danger ea-btn--small"
											onClick={ () =>
												handleDelete( idp.id )
											}
										>
											Delete
										</button>
									</td>
								</tr>
							) ) }
						</tbody>
					</table>
				) }
			</div>
		</div>
	);
}
