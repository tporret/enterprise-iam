import { useCallback, useEffect } from '@wordpress/element';

const SAML_PRESETS = [
	{
		id: 'standard-okta-saml',
		label: 'Standard / Okta',
		families: [ 'okta' ],
		email: 'email',
		first_name: 'firstName',
		last_name: 'lastName',
	},
	{
		id: 'azure-ad-saml',
		label: 'Azure AD (Microsoft Entra)',
		families: [ 'microsoft-entra' ],
		email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
		first_name:
			'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
		last_name:
			'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
	},
	{
		id: 'shibboleth-saml',
		label: 'Shibboleth / InCommon (OIDs)',
		families: [ 'shibboleth' ],
		email: 'urn:oid:0.9.2342.19200300.100.1.3',
		first_name: 'urn:oid:2.5.4.42',
		last_name: 'urn:oid:2.5.4.4',
	},
];

const OIDC_PRESETS = [
	{
		id: 'standard-oidc',
		label: 'Standard OIDC (Okta / Google / Auth0)',
		families: [ 'google', 'okta', 'auth0' ],
		email: 'email',
		first_name: 'given_name',
		last_name: 'family_name',
	},
	{
		id: 'azure-ad-oidc',
		label: 'Azure AD OIDC',
		families: [ 'microsoft-entra' ],
		email: 'preferred_username',
		first_name: 'given_name',
		last_name: 'family_name',
	},
];

/**
 * Reusable "Override Default Attribute Mapping" section for SAML & OIDC forms.
 *
 * @param {Object}   props
 * @param {'saml'|'oidc'} props.protocol
 * @param {string}   props.providerFamily        Normalized provider family.
 * @param {boolean}  props.overrideMapping      Toggle state.
 * @param {string}   props.customEmailAttr      Custom email attribute key.
 * @param {string}   props.customFirstNameAttr  Custom first-name attribute key.
 * @param {string}   props.customLastNameAttr   Custom last-name attribute key.
 * @param {Function} props.onUpdateField        (key, value) callback.
 */
export default function AttributeMappingSection( {
	protocol,
	providerFamily,
	overrideMapping,
	customEmailAttr,
	customFirstNameAttr,
	customLastNameAttr,
	onUpdateField,
} ) {
	const presets = protocol === 'saml' ? SAML_PRESETS : OIDC_PRESETS;
	const normalizedProviderFamily = providerFamily || 'generic';
	const recommendedPreset = presets.find( ( preset ) =>
		Array.isArray( preset.families ) && preset.families.includes( normalizedProviderFamily )
	);

	const applyPreset = useCallback(
		( preset ) => {
			if ( ! preset ) {
				return;
			}

			onUpdateField( 'custom_email_attr', preset.email );
			onUpdateField( 'custom_first_name_attr', preset.first_name );
			onUpdateField( 'custom_last_name_attr', preset.last_name );
		},
		[ onUpdateField ]
	);

	const handlePreset = useCallback(
		( e ) => {
			const presetId = e.target.value;
			if ( ! presetId ) {
				return;
			}
			const preset = presets.find( ( item ) => item.id === presetId );
			if ( ! preset ) {
				return;
			}
			applyPreset( preset );
		},
		[ presets, applyPreset ]
	);

	useEffect( () => {
		if ( ! overrideMapping || ! recommendedPreset ) {
			return;
		}

		if ( customEmailAttr || customFirstNameAttr || customLastNameAttr ) {
			return;
		}

		applyPreset( recommendedPreset );
	}, [
		overrideMapping,
		recommendedPreset,
		customEmailAttr,
		customFirstNameAttr,
		customLastNameAttr,
		applyPreset,
	] );

	return (
		<div className="ea-form-group">
			<label className="ea-label ea-label--toggle">
				<input
					type="checkbox"
					checked={ overrideMapping }
					onChange={ ( e ) =>
						onUpdateField(
							'override_attribute_mapping',
							e.target.checked
						)
					}
				/>
				<span>Override Default Attribute Mapping</span>
			</label>

			{ overrideMapping && (
				<div className="ea-attr-mapping">
					{ recommendedPreset && (
						<div className="ea-form-group">
							<label className="ea-label">Recommended Preset</label>
							<div className="ea-discovery__row">
								<input
									type="text"
									className="ea-input"
									value={ recommendedPreset.label }
									readOnly
								/>
								<button
									type="button"
									className="ea-btn ea-btn--secondary ea-btn--small"
									onClick={ () => applyPreset( recommendedPreset ) }
								>
									Use Recommended Preset
								</button>
							</div>
						</div>
					)}

					<div className="ea-attr-mapping__preset">
						<label className="ea-label">Load Preset</label>
						<select
							className="ea-input"
							defaultValue=""
							onChange={ handlePreset }
						>
							<option value="" disabled>
								— Select IdP Preset —
							</option>
							{ presets.map( ( p ) => (
								<option key={ p.id } value={ p.id }>
									{ p.label }
								</option>
							) ) }
						</select>
					</div>

					<div className="ea-form-group">
						<label className="ea-label">
							Email Attribute Key
						</label>
						<input
							type="text"
							className="ea-input ea-input--mono"
							placeholder={
								protocol === 'saml' ? 'email' : 'email'
							}
							value={ customEmailAttr }
							onChange={ ( e ) =>
								onUpdateField(
									'custom_email_attr',
									e.target.value
								)
							}
						/>
					</div>

					<div className="ea-form-group">
						<label className="ea-label">
							First Name Attribute Key
						</label>
						<input
							type="text"
							className="ea-input ea-input--mono"
							placeholder={
								protocol === 'saml'
									? 'firstName'
									: 'given_name'
							}
							value={ customFirstNameAttr }
							onChange={ ( e ) =>
								onUpdateField(
									'custom_first_name_attr',
									e.target.value
								)
							}
						/>
					</div>

					<div className="ea-form-group">
						<label className="ea-label">
							Last Name Attribute Key
						</label>
						<input
							type="text"
							className="ea-input ea-input--mono"
							placeholder={
								protocol === 'saml'
									? 'lastName'
									: 'family_name'
							}
							value={ customLastNameAttr }
							onChange={ ( e ) =>
								onUpdateField(
									'custom_last_name_attr',
									e.target.value
								)
							}
						/>
					</div>
				</div>
			) }
		</div>
	);
}
