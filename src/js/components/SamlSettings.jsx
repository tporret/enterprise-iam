import { useState, useCallback } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import AttributeMappingSection from './AttributeMappingSection';

const WP_ROLES = [
	{ value: 'editor', label: 'Editor' },
	{ value: 'author', label: 'Author' },
	{ value: 'contributor', label: 'Contributor' },
	{ value: 'subscriber', label: 'Subscriber' },
];

const SAML_PROVIDER_OPTIONS = [
	{ value: 'generic', label: 'Generic SAML' },
	{ value: 'microsoft-entra', label: 'Microsoft Entra ID' },
	{ value: 'okta', label: 'Okta' },
	{ value: 'ping', label: 'Ping Identity' },
	{ value: 'shibboleth', label: 'Shibboleth / InCommon' },
];

const EMPTY_IDP = {
	id: '',
	provider_name: '',
	provider_family: 'generic',
	protocol: 'saml',
	entity_id: '',
	sso_url: '',
	slo_url: '',
	certificate: '',
	domain_mapping: [],
	role_mapping: {},
	enabled: true,
	client_id: '',
	client_secret: '',
	authorization_endpoint: '',
	token_endpoint: '',
	userinfo_endpoint: '',
	force_reauth: false,
};

function CopyField( { label, value } ) {
	const [ copied, setCopied ] = useState( false );

	const handleCopy = useCallback( () => {
		navigator.clipboard.writeText( value ).then( () => {
			setCopied( true );
			setTimeout( () => setCopied( false ), 1500 );
		} );
	}, [ value ] );

	return (
		<div className="ea-copy-field">
			<label className="ea-copy-field__label">{ label }</label>
			<div className="ea-copy-field__row">
				<code className="ea-copy-field__value">{ value }</code>
				<button
					type="button"
					className="ea-btn ea-btn--small"
					onClick={ handleCopy }
				>
					{ copied ? 'Copied!' : 'Copy' }
				</button>
			</div>
		</div>
	);
}

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

export default function SamlSettings( { showToast } ) {
	const [ idps, setIdps ] = useState( [] );
	const [ loaded, setLoaded ] = useState( false );
	const [ editing, setEditing ] = useState( null ); // null | idp object
	const [ saving, setSaving ] = useState( false );
	const [ roleMappings, setRoleMappings ] = useState( [] ); // [{ group, role }]
	const [ domainText, setDomainText ] = useState( '' );

	const siteUrl = window.location.origin;
	const acsUrl = `${ siteUrl }/wp-json/enterprise-auth/v1/saml/acs`;
	const metadataUrl = `${ siteUrl }/wp-json/enterprise-auth/v1/saml/metadata`;

	// Load IdPs on mount (filter to SAML only for display).
	const loadIdps = useCallback( () => {
		apiFetch( { path: 'enterprise-auth/v1/idps' } )
			.then( ( data ) => {
				const all = Array.isArray( data ) ? data : [];
				setIdps( all.filter( ( idp ) => idp.protocol === 'saml' ) );
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

	const startEdit = useCallback(
		( idp ) => {
			const mapped = Object.entries( idp.role_mapping || {} ).map(
				( [ group, role ] ) => ( { group, role } )
			);
			setEditing( { ...idp } );
			setRoleMappings(
				mapped.length > 0 ? mapped : [ { group: '', role: 'subscriber' } ]
			);
			setDomainText( ( idp.domain_mapping || [] ).join( ', ' ) );
		},
		[]
	);

	const startNew = useCallback( () => {
		startEdit( { ...EMPTY_IDP } );
	}, [ startEdit ] );

	const cancelEdit = useCallback( () => {
		setEditing( null );
		setRoleMappings( [] );
		setDomainText( '' );
	}, [] );

	const updateField = useCallback(
		( key, value ) => {
			setEditing( ( prev ) => ( { ...prev, [ key ]: value } ) );
		},
		[]
	);

	/**
	 * Parse an IdP metadata XML file and auto-fill the form.
	 */
	const handleMetadataUpload = useCallback(
		( e ) => {
			const file = e.target.files?.[ 0 ];
			if ( ! file ) {
				return;
			}

			const reader = new FileReader();
			reader.onload = ( evt ) => {
				try {
					const parser = new DOMParser();
					const doc = parser.parseFromString(
						evt.target.result,
						'application/xml'
					);

					const parseError = doc.querySelector( 'parsererror' );
					if ( parseError ) {
						showToast( 'Invalid XML file.', 'error' );
						return;
					}

					// EntityID — from <EntityDescriptor entityID="...">
					const entityDesc =
						doc.querySelector( 'EntityDescriptor' ) ||
						doc.getElementsByTagNameNS(
							'urn:oasis:names:tc:SAML:2.0:metadata',
							'EntityDescriptor'
						)[ 0 ];

					const entityId = entityDesc?.getAttribute( 'entityID' ) || '';

					// SSO URL — from <SingleSignOnService Location="...">
					// Prefer HTTP-Redirect binding.
					const ssoElements = [
						...doc.querySelectorAll( 'SingleSignOnService' ),
						...doc.getElementsByTagNameNS(
							'urn:oasis:names:tc:SAML:2.0:metadata',
							'SingleSignOnService'
						),
					];
					let ssoUrl = '';
					for ( const el of ssoElements ) {
						const binding = el.getAttribute( 'Binding' ) || '';
						const loc = el.getAttribute( 'Location' ) || '';
						if (
							binding.includes( 'HTTP-Redirect' ) ||
							! ssoUrl
						) {
							ssoUrl = loc;
						}
						if ( binding.includes( 'HTTP-Redirect' ) ) {
							break;
						}
					}

					// x509 Certificate — from <X509Certificate>
					const certEl =
						doc.querySelector( 'X509Certificate' ) ||
						doc.getElementsByTagNameNS(
							'http://www.w3.org/2000/09/xmldsig#',
							'X509Certificate'
						)[ 0 ];
					const certificate = certEl?.textContent?.trim() || '';

					// SLO URL — from <SingleLogoutService Location="...">
					const sloElements = [
						...doc.querySelectorAll( 'SingleLogoutService' ),
						...doc.getElementsByTagNameNS(
							'urn:oasis:names:tc:SAML:2.0:metadata',
							'SingleLogoutService'
						),
					];
					let sloUrl = '';
					for ( const el of sloElements ) {
						const binding = el.getAttribute( 'Binding' ) || '';
						const loc = el.getAttribute( 'Location' ) || '';
						if (
							binding.includes( 'HTTP-Redirect' ) ||
							! sloUrl
						) {
							sloUrl = loc;
						}
						if ( binding.includes( 'HTTP-Redirect' ) ) {
							break;
						}
					}

					// Auto-fill the form.
					setEditing( ( prev ) => ( {
						...prev,
						entity_id: entityId || prev.entity_id,
						sso_url: ssoUrl || prev.sso_url,
						slo_url: sloUrl || prev.slo_url,
						certificate: certificate || prev.certificate,
					} ) );

					showToast( 'Metadata imported — fields auto-filled.' );
				} catch {
					showToast( 'Failed to parse metadata file.', 'error' );
				}
			};
			reader.readAsText( file );

			// Reset the input so the same file can be re-selected.
			e.target.value = '';
		},
		[ showToast ]
	);

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

	const handleSave = useCallback( async () => {
		if ( ! editing ) {
			return;
		}

		setSaving( true );

		// Build role_mapping object from array.
		const role_mapping = {};
		roleMappings.forEach( ( { group, role } ) => {
			const g = group.trim();
			if ( g ) {
				role_mapping[ g ] = role;
			}
		} );

		// Parse domain_mapping.
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

			showToast( 'SAML configuration saved successfully.' );
			cancelEdit();
			loadIdps();
		} catch ( error ) {
			showToast(
				error?.message || 'Failed to save SAML configuration.',
				'error'
			);
		} finally {
			setSaving( false );
		}
	}, [ editing, roleMappings, domainText, showToast, cancelEdit, loadIdps ] );

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
		return <p style={ { color: '#64748b' } }>Loading SAML settings&hellip;</p>;
	}

	// ── Editing form ──────────────────────────────────────────────────
	if ( editing ) {
		return (
			<div className="ea-saml">
				<h2 className="ea-saml__heading">
					{ editing.id ? 'Edit IdP Configuration' : 'New IdP Configuration' }
				</h2>

				<div className="ea-upload-meta">
					<label className="ea-btn ea-btn--secondary ea-btn--small ea-upload-meta__label">
						&#x2B06; Upload IdP Metadata XML
						<input
							type="file"
							accept=".xml,application/xml,text/xml"
							className="ea-upload-meta__input"
							onChange={ handleMetadataUpload }
						/>
					</label>
					<span className="ea-upload-meta__hint">
						Auto-fills Entity ID, SSO URL, and Certificate from a
						standard SAML metadata file.
					</span>
				</div>

				<div className="ea-form-group">
					<label className="ea-label">Connection Name</label>
					<input
						type="text"
						className="ea-input"
						placeholder="e.g. Corporate Entra ID"
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
						{ SAML_PROVIDER_OPTIONS.map( ( option ) => (
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
					<label className="ea-label">IdP Entity ID</label>
					<input
						type="text"
						className="ea-input"
						placeholder="https://idp.example.com/metadata"
						value={ editing.entity_id }
						onChange={ ( e ) =>
							updateField( 'entity_id', e.target.value )
						}
					/>
				</div>

				<div className="ea-form-group">
					<label className="ea-label">
						Single Sign-On Service (SSO) URL
					</label>
					<input
						type="text"
						className="ea-input"
						placeholder="https://idp.example.com/sso"
						value={ editing.sso_url }
						onChange={ ( e ) =>
							updateField( 'sso_url', e.target.value )
						}
					/>
				</div>

				<div className="ea-form-group">
					<label className="ea-label">x509 Certificate</label>
					<textarea
						className="ea-input ea-textarea"
						rows={ 6 }
						placeholder="Paste the IdP public certificate here"
						value={ editing.certificate }
						onChange={ ( e ) =>
							updateField( 'certificate', e.target.value )
						}
					/>
				</div>

				<AttributeMappingSection
					protocol="saml"
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
							(comma-separated, e.g. acme.com, subsidiary.org)
						</span>
					</label>
					<input
						type="text"
						className="ea-input"
						placeholder="acme.com, subsidiary.org"
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
						When enabled, SAML AuthnRequests include ForceAuthn=true,
						requiring the user to re-authenticate at the IdP even if
						they have an active IdP session.
					</p>
				</div>

				<div className="ea-form-group">
					<label className="ea-label">Single Logout (SLO) URL</label>
					<input
						type="text"
						className="ea-input"
						placeholder="https://idp.example.com/saml/slo"
						value={ editing.slo_url || '' }
						onChange={ ( e ) =>
							updateField( 'slo_url', e.target.value )
						}
					/>
					<p className="ea-label__hint" style={ { margin: '4px 0 0' } }>
						When set, WordPress logout will redirect to the IdP&rsquo;s
						SLO endpoint to also terminate the IdP session.
					</p>
				</div>

				<div className="ea-form-actions">
					<button
						type="button"
						className="ea-btn ea-btn--primary"
						disabled={ saving }
						onClick={ handleSave }
					>
						{ saving ? 'Saving…' : 'Save Configuration' }
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
			{ /* SP Metadata read-only section */ }
			<div className="ea-card" style={ { marginBottom: 20 } }>
				<h3 className="ea-card__title">Service Provider (SP) Metadata</h3>
				<p className="ea-card__desc" style={ { marginBottom: 12 } }>
					Provide these values to your Identity Provider administrator.
				</p>
				<CopyField label="Entity ID" value={ siteUrl } />
				<CopyField label="ACS URL" value={ acsUrl } />
				<CopyField label="Metadata URL" value={ metadataUrl } />
			</div>

			{ /* IdP list */ }
			<div className="ea-card">
				<div className="ea-card__body" style={ { justifyContent: 'space-between', alignItems: 'center' } }>
					<h3 className="ea-card__title" style={ { margin: 0 } }>
						Identity Providers
					</h3>
					<button
						type="button"
						className="ea-btn ea-btn--primary ea-btn--small"
						onClick={ startNew }
					>
						+ Add IdP
					</button>
				</div>

				{ idps.length === 0 && (
					<p className="ea-card__desc" style={ { marginTop: 12 } }>
						No IdPs configured yet. Click &ldquo;Add IdP&rdquo; to
						set up your first SAML connection.
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
									<td>{ idp.provider_name || '(Untitled)' }</td>
									<td>
										{ ( idp.domain_mapping || [] ).join( ', ' ) || '—' }
									</td>
									<td>
										<span
											className={ `ea-badge ${ idp.enabled ? 'ea-badge--active' : 'ea-badge--inactive' }` }
										>
											{ idp.enabled ? 'Active' : 'Inactive' }
										</span>
									</td>
									<td>
										<button
											type="button"
											className="ea-btn ea-btn--secondary ea-btn--small"
											onClick={ () => startEdit( idp ) }
										>
											Edit
										</button>{ ' ' }
										<button
											type="button"
											className="ea-btn ea-btn--danger ea-btn--small"
											onClick={ () => handleDelete( idp.id ) }
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
