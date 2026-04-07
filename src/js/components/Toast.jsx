import { useEffect } from '@wordpress/element';

export default function Toast( { message, type = 'success', onDismiss } ) {
	useEffect( () => {
		const timer = setTimeout( onDismiss, 3000 );
		return () => clearTimeout( timer );
	}, [ onDismiss ] );

	const className = `ea-toast ea-toast--${ type }`;

	return (
		<div className={ className } role="status" aria-live="polite">
			<span className="ea-toast__msg">{ message }</span>
			<button
				className="ea-toast__close"
				type="button"
				onClick={ onDismiss }
				aria-label="Dismiss"
			>
				&times;
			</button>
		</div>
	);
}
