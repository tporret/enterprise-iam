export default function IdpListCard( {
	readOnlyNotice,
	listTitle,
	allowMutations,
	addButtonLabel,
	onAdd,
	idps,
	emptyMessage,
	emptyFallback,
	showAssignmentCount,
	onEdit,
	onDelete,
} ) {
	return (
		<div className="ea-card">
			{ readOnlyNotice && (
				<p className="ea-card__desc ea-card__desc--notice">{ readOnlyNotice }</p>
			) }
			<div className="ea-card__body" style={ { justifyContent: 'space-between', alignItems: 'center' } }>
				<h3 className="ea-card__title" style={ { margin: 0 } }>
					{ listTitle }
				</h3>
				{ allowMutations && (
					<button
						type="button"
						className="ea-btn ea-btn--primary ea-btn--small"
						onClick={ onAdd }
					>
						{ addButtonLabel }
					</button>
				) }
			</div>

			{ idps.length === 0 && (
				<p className="ea-card__desc" style={ { marginTop: 12 } }>
					{ emptyMessage || emptyFallback }
				</p>
			) }

			{ idps.length > 0 && (
				<table className="ea-idp-table">
					<thead>
						<tr>
							<th>Name</th>
							<th>Domains</th>
							{ showAssignmentCount && <th>Sites</th> }
							<th>Status</th>
							{ allowMutations && <th>Actions</th> }
						</tr>
					</thead>
					<tbody>
						{ idps.map( ( idp ) => (
							<tr key={ idp.id }>
								<td>{ idp.provider_name || '(Untitled)' }</td>
								<td>{ ( idp.domain_mapping || [] ).join( ', ' ) || '\u2014' }</td>
								{ showAssignmentCount && <td>{ idp.assignment_count || 0 }</td> }
								<td>
									<span className={ `ea-badge ${ idp.enabled ? 'ea-badge--active' : 'ea-badge--inactive' }` }>
										{ idp.enabled ? 'Active' : 'Inactive' }
									</span>
								</td>
								{ allowMutations && (
									<td>
										<button
											type="button"
											className="ea-btn ea-btn--secondary ea-btn--small"
											onClick={ () => onEdit( idp.id ) }
										>
											Edit
										</button>{ ' ' }
										<button
											type="button"
											className="ea-btn ea-btn--danger ea-btn--small"
											onClick={ () => onDelete( idp.id ) }
										>
											Delete
										</button>
									</td>
								) }
							</tr>
						) ) }
					</tbody>
				</table>
			) }
		</div>
	);
}
