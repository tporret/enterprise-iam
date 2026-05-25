import { createRoot } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import App from './App';
import SelfEnrollmentApp from './SelfEnrollmentApp';
import StepUpApp from './StepUpApp';
import { installStepUpApiFetchMiddleware } from './step-up-api-fetch';
import './style.css';

if ( window.enterpriseAuth?.nonce ) {
	apiFetch.use( apiFetch.createNonceMiddleware( window.enterpriseAuth.nonce ) );
}
installStepUpApiFetchMiddleware();

const container = document.getElementById( 'enterprise-auth-root' );
if ( container ) {
	const screen = window.enterpriseAuth?.screen;
	const RootComponent = screen === 'stepup' ? StepUpApp : screen === 'self-enrollment' ? SelfEnrollmentApp : App;
	createRoot( container ).render( <RootComponent /> );
}
