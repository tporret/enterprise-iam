const DEFAULT_WP_ROLES = [
	{ value: 'editor', label: 'Editor' },
	{ value: 'author', label: 'Author' },
	{ value: 'contributor', label: 'Contributor' },
	{ value: 'subscriber', label: 'Subscriber' },
];

export const WP_ROLES = DEFAULT_WP_ROLES;

export default function RoleMappingRow( {
	group,
	role,
	onChange,
	onRemove,
	roles = DEFAULT_WP_ROLES,
} ) {
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
				{ roles.map( ( r ) => (
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
