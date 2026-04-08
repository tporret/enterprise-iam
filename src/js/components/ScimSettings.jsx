import { useState, useRef, useCallback } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

export default function ScimSettings( { showToast } ) {
	const [ generating, setGenerating ] = useState( false );
	const [ token, setToken ] = useState( null );
	const [ baseUrl, setBaseUrl ] = useState(
		window.enterpriseAuth.restUrl + 'scim/v2/'
	);
	const tokenRef = useRef( null );

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
