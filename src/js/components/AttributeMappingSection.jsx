import { useCallback } from '@wordpress/element';

const SAML_PRESETS = [
	{
		label: 'Standard / Okta',
		email: 'email',
		first_name: 'firstName',
		last_name: 'lastName',
	},
	{
		label: 'Azure AD (Microsoft Entra)',
		email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
		first_name:
			'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
		last_name:
			'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
	},
	{
		label: 'Shibboleth / InCommon (OIDs)',
		email: 'urn:oid:0.9.2342.19200300.100.1.3',
		first_name: 'urn:oid:2.5.4.42',
		last_name: 'urn:oid:2.5.4.4',
	},
];

const OIDC_PRESETS = [
	{
		label: 'Standard OIDC (Okta / Google / Auth0)',
		email: 'email',
		first_name: 'given_name',
		last_name: 'family_name',
	},
	{
		label: 'Azure AD OIDC',
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
 * @param {boolean}  props.overrideMapping      Toggle state.
 * @param {string}   props.customEmailAttr      Custom email attribute key.
 * @param {string}   props.customFirstNameAttr  Custom first-name attribute key.
 * @param {string}   props.customLastNameAttr   Custom last-name attribute key.
 * @param {Function} props.onUpdateField        (key, value) callback.
 */
export default function AttributeMappingSection( {
	protocol,
	overrideMapping,
	customEmailAttr,
	customFirstNameAttr,
	customLastNameAttr,
	onUpdateField,
} ) {
	const presets = protocol === 'saml' ? SAML_PRESETS : OIDC_PRESETS;

	const handlePreset = useCallback(
		( e ) => {
			const idx = parseInt( e.target.value, 10 );
			if ( isNaN( idx ) || idx < 0 ) {
				return;
			}
			const p = presets[ idx ];
			if ( ! p ) {
				return;
			}
			onUpdateField( 'custom_email_attr', p.email );
			onUpdateField( 'custom_first_name_attr', p.first_name );
			onUpdateField( 'custom_last_name_attr', p.last_name );
		},
		[ presets, onUpdateField ]
	);

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
							{ presets.map( ( p, i ) => (
								<option key={ p.label } value={ i }>
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
