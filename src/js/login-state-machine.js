export function LoginStateMachine() {
	var state = {
		step: 'email_entry',
		passkeyStatus: 'idle',
	};

	function transition( action ) {
		switch ( action.type ) {
			case 'RESUME_LOCAL_FLOW':
			case 'ROUTE_TO_LOCAL':
				return {
					step: 'local_auth',
					passkeyStatus: 'idle',
				};
			case 'BACK_TO_EMAIL_ENTRY':
				return {
					step: 'email_entry',
					passkeyStatus: 'idle',
				};
			case 'START_PASSKEY':
				return {
					step: state.step,
					passkeyStatus: 'pending',
				};
			case 'PASSKEY_SUCCESS':
				return {
					step: state.step,
					passkeyStatus: 'success',
				};
			case 'PASSKEY_FAILURE':
			case 'PASSKEY_CANCELLED':
				return {
					step: state.step,
					passkeyStatus: 'error',
				};
			case 'FALLBACK_SSO':
				return {
					step: 'email_entry',
					passkeyStatus: 'idle',
				};
			default:
				return state;
		}
	}

	return {
		getState: function () {
			return state;
		},
		dispatch: function ( action ) {
			state = transition( action );
			return state;
		},
	};
}
