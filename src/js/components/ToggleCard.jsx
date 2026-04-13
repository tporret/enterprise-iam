export default function ToggleCard( {
	title,
	description,
	checked,
	disabled,
	onChange,
	scopeLabel = '',
	scopeTone = 'site-only',
	metaDescription = '',
} ) {
	const id = `ea-toggle-${ title.replace( /\s+/g, '-' ).toLowerCase() }`;

	return (
		<div className={ `ea-card${ checked ? ' ea-card--active' : '' }` }>
			<div className="ea-card__body">
				<div className="ea-card__text">
					<div className="ea-setting-header">
						<h2 className="ea-card__title">{ title }</h2>
						{ scopeLabel && (
							<span className={ `ea-scope-tag ea-scope-tag--${ scopeTone }` }>
								{ scopeLabel }
							</span>
						) }
					</div>
					<p className="ea-card__desc">{ description }</p>
					{ metaDescription && (
						<p className="ea-scope-meta">{ metaDescription }</p>
					) }
				</div>
				<label className="ea-toggle" htmlFor={ id }>
					<input
						id={ id }
						className="ea-toggle__input"
						type="checkbox"
						checked={ checked }
						disabled={ disabled }
						onChange={ ( event ) => onChange( event.target.checked ) }
					/>
					<span className="ea-toggle__slider" />
					<span className="screen-reader-text">
						{ checked ? 'Enabled' : 'Disabled' }
					</span>
				</label>
			</div>
		</div>
	);
}
