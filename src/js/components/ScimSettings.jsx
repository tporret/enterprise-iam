import { useState, useRef, useCallback } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

export default function ScimSettings( { showToast, settings, saving, updateSetting, scopeMeta = null } ) {
	const [ generating, setGenerating ] = useState( false );
	const [ token, setToken ] = useState( null );
	const [ baseUrl, setBaseUrl ] = useState(
		window.enterpriseAuth.restUrl + 'scim/v2/'
	);
	const tokenRef = useRef( null );
	const stewardOptions = settings?.deprovision_steward_options ?? [];

	const generateToken = useCallback( async () => {
		setGenerating( true );
		setToken( null );

		try {
			const data = await apiFetch( {
				path: 'enterprise-auth/v1/settings/scim-token',
				method: 'POST',
			} );

			setToken( data.token );
			setBaseUrl( data.base_url );
			showToast( 'SCIM token generated successfully.' );
		} catch {
			showToast( 'Failed to generate SCIM token.', 'error' );
		} finally {
			setGenerating( false );
		}
	}, [ showToast ] );

	const copyToken = useCallback( () => {
		if ( tokenRef.current ) {
			tokenRef.current.select();
			navigator.clipboard.writeText( tokenRef.current.value ).then( () => {
				setToken( null );
				showToast( 'Token copied to clipboard.' );
			} );
		}
	}, [ showToast ] );

	const copyBaseUrl = useCallback( () => {
		navigator.clipboard.writeText( baseUrl ).then( () => {
			showToast( 'Base URL copied to clipboard.' );
		} );
	}, [ baseUrl, showToast ] );

	return (
		<section className="ea-card-grid">
			<div className="ea-card ea-card--wide">
				<h3 className="ea-card__title">SCIM Base URL</h3>
				<p className="ea-card__desc">
					Provide this URL to your Identity Provider as the SCIM
					connector base URL.
				</p>
				<div className="ea-scim-url-row">
					<code className="ea-scim-url">{ baseUrl }</code>
					<button
						type="button"
						className="ea-btn ea-btn--sm"
						onClick={ copyBaseUrl }
					>
						Copy
					</button>
				</div>
			</div>

			<div className="ea-card ea-card--wide">
				<h3 className="ea-card__title">Bearer Token</h3>
				<p className="ea-card__desc">
					Generate a token for your IdP to authenticate SCIM
					requests. Only the bcrypt hash is stored — the plaintext
					is shown once and cannot be retrieved later.
				</p>

				<button
					type="button"
					className="ea-btn"
					disabled={ generating }
					onClick={ generateToken }
				>
					{ generating
						? 'Generating…'
						: 'Generate New SCIM Token' }
				</button>

				{ token && (
					<div className="ea-scim-token-result">
						<div className="ea-scim-token-warning">
							⚠ Copy this token now. It will never be displayed
							again.
						</div>
						<div className="ea-scim-url-row">
							<input
								ref={ tokenRef }
								className="ea-input ea-input--mono"
								type="text"
								readOnly
								value={ token }
							/>
							<button
								type="button"
								className="ea-btn ea-btn--sm"
								onClick={ copyToken }
							>
								Copy
							</button>
						</div>
					</div>
				) }
			</div>

			<div className="ea-card ea-card--wide">
				<div className="ea-setting-header">
					<h3 className="ea-card__title">Deprovision Steward</h3>
					{ scopeMeta?.label && (
						<span className={ `ea-scope-tag ea-scope-tag--${ scopeMeta.tone || 'site-only' }` }>
							{ scopeMeta.label }
						</span>
					) }
				</div>
				<p className="ea-card__desc">
					When SCIM deprovisions a user who still owns content on this
					site, Enterprise Auth reassigns that content to this steward.
					If no steward is configured, the plugin falls back to a
					deterministic local administrator. If no valid steward is
					available, the delete request fails with a 409 response.
				</p>
				{ scopeMeta?.description && (
					<p className="ea-scope-meta">{ scopeMeta.description }</p>
				) }
				<select
					className="ea-input"
					value={ settings?.deprovision_steward_user_id ?? 0 }
					disabled={ saving }
					onChange={ ( event ) => updateSetting( 'deprovision_steward_user_id', parseInt( event.target.value, 10 ) ) }
				>
					<option value={ 0 }>
						Auto-resolve from local administrators
					</option>
					{ stewardOptions.map( ( option ) => (
						<option key={ option.id } value={ option.id }>
							{ option.label }
						</option>
					) ) }
				</select>
				<p className="ea-card__desc">
					Network deprovision mode evaluates this policy independently on
					each site before removing memberships.
				</p>
			</div>

			<div className="ea-card ea-card--wide">
				<h3 className="ea-card__title">Supported Endpoints</h3>
				<p className="ea-card__desc">
					These SCIM 2.0 endpoints are available for your IdP
					provisioning connector.
				</p>
				<table className="ea-scim-endpoints">
					<thead>
						<tr>
							<th>Method</th>
							<th>Path</th>
							<th>Description</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td><code>POST</code></td>
							<td><code>/Users</code></td>
							<td>Create a new user</td>
						</tr>
						<tr>
							<td><code>PUT</code></td>
							<td><code>/Users/&#123;id&#125;</code></td>
							<td>Replace user attributes</td>
						</tr>
						<tr>
							<td><code>PATCH</code></td>
							<td><code>/Users/&#123;id&#125;</code></td>
							<td>
								Suspend / reactivate (active flag)
							</td>
						</tr>
						<tr>
							<td><code>DELETE</code></td>
							<td><code>/Users/&#123;id&#125;</code></td>
							<td>Remove the user from the current site</td>
						</tr>
						<tr>
							<td><code>DELETE</code></td>
							<td><code>/Users/&#123;id&#125;?scope=network</code></td>
							<td>Deprovision the user across every site in the network</td>
						</tr>
						<tr>
							<td><code>POST</code></td>
							<td><code>/Groups</code></td>
							<td>Create group &amp; assign roles</td>
						</tr>
						<tr>
							<td><code>PATCH</code></td>
							<td><code>/Groups/&#123;id&#125;</code></td>
							<td>Update group membership</td>
						</tr>
					</tbody>
				</table>
			</div>
		</section>
	);
}
