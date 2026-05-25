import { useCallback, useState } from '@wordpress/element';
import PasskeySection from './components/PasskeySection';
import Toast from './components/Toast';

export default function SelfEnrollmentApp() {
	const [ toast, setToast ] = useState( null );
	const showToast = useCallback( ( message, type = 'success' ) => {
		setToast( { message, type } );
	}, [] );

	return (
		<div className="ea-self-enrollment">
			<div className="ea-card">
				<h1 className="ea-card__title">Your Passkeys</h1>
				<p className="ea-card__desc">
					Register a passkey for faster sign-in and tenant security checks. Enrollment is tied to your WordPress account and follows the active enterprise assurance policy.
				</p>
			</div>
			<PasskeySection
				showToast={ showToast }
				title="Register a Passkey"
				description="Use the authenticator built into this device to add a passkey to your account."
				buttonLabel="Register Passkey"
				successMessage="Passkey registered successfully."
				cancelledMessage="Passkey registration was cancelled."
				unsupportedMessage="This browser cannot perform passkey enrollment. Use a current browser with WebAuthn support."
				policyItems={ [
					'Enrollment always applies to your signed-in WordPress account.',
					'Your organization may require a built-in device authenticator with verifiable attestation.',
					'If device-bound mode is enabled, synced backup-eligible passkeys are not accepted.',
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