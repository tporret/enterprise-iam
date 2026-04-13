import { createRoot } from '@wordpress/element';
import App from './App';
import StepUpApp from './StepUpApp';
import './style.css';

const container = document.getElementById( 'enterprise-auth-root' );
if ( container ) {
	const RootComponent = window.enterpriseAuth?.screen === 'stepup' ? StepUpApp : App;
	createRoot( container ).render( <RootComponent /> );
}
