import { useCallback, useState } from '@wordpress/element';
import PasskeySection from './components/PasskeySection';
import Toast from './components/Toast';

export default function StepUpApp() {
	const [ toast, setToast ] = useState( null );
	const showToast = useCallback( ( message, type = 'success' ) => {
		setToast( { message, type } );
	}, [] );

	return (
		<div className="ea-stepup">
			<div className="ea-card">
				<h1 className="ea-card__title">Security Upgrade Required</h1>
				<p className="ea-card__desc">
					Your organization now requires a device-bound passkey for this tenant.
					Finish this upgrade before continuing to other WordPress pages.
				</p>
				<p className="ea-stepup__meta">
					The passkey you used most recently is no longer compliant with the active
					tenant assurance policy. Register a new device-bound passkey on this managed
					device to complete the migration.
				</p>
				<div className="ea-stepup__actions">
					<span className="ea-stepup__meta">You will be redirected automatically after a successful upgrade.</span>
					<a className="ea-stepup__link" href={ window.enterpriseAuth?.logoutUrl || '/wp-login.php?action=logout' }>
						Sign out instead
					</a>
				</div>
			</div>
			<PasskeySection
				showToast={ showToast }
				requireDeviceBound={ true }
				title="Register Your Device-Bound Passkey"
				description="Use the platform authenticator built into this managed device to finish the tenant security upgrade."
				buttonLabel="Register Device-Bound Passkey"
				successMessage="Security upgrade complete. Redirecting…"
				cancelledMessage="The security upgrade was cancelled before a compliant passkey was registered."
				unsupportedMessage="This browser cannot complete the required device-bound passkey upgrade. Use a current managed browser on the target device."
				policyItems={ [
					'Only built-in platform authenticators with direct attestation are accepted for this upgrade.',
					'Backup-eligible synced passkeys are not permitted while this tenant requires device-bound authenticators.',
					'Once a compliant passkey is saved, older legacy passkeys for this tenant are automatically revoked.',
				] }
			/>
			{ toast && (
				<Toast
					message={ toast.message }
					type={ toast.type }
					onDismiss={ () => setToast( null ) }
				/>
			) }
		</div>
	);
}