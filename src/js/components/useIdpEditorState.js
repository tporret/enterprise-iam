import { useState, useEffect, useCallback } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

export default function useIdpEditorState( {
	endpointBase,
	protocol,
	showToast,
	emptyIdp,
	onEditorChanged,
} ) {
	const [ idps, setIdps ] = useState( [] );
	const [ loaded, setLoaded ] = useState( false );
	const [ editing, setEditing ] = useState( null );
	const [ roleMappings, setRoleMappings ] = useState( [] );
	const [ domainText, setDomainText ] = useState( '' );

	const loadIdps = useCallback( () => {
		apiFetch( { path: endpointBase } )
			.then( ( data ) => {
				const all = Array.isArray( data ) ? data : [];
				setIdps( all.filter( ( idp ) => idp.protocol === protocol ) );
				setLoaded( true );
			} )
			.catch( () => {
				setLoaded( true );
			} );
	}, [ endpointBase, protocol ] );

	useEffect( () => {
		loadIdps();
	}, [ loadIdps ] );

	const openEditor = useCallback(
		( idp ) => {
			const mapped = Object.entries( idp.role_mapping || {} ).map(
				( [ group, role ] ) => ( { group, role } )
			);
			setEditing( { ...idp } );
			setRoleMappings(
				mapped.length > 0 ? mapped : [ { group: '', role: 'subscriber' } ]
			);
			setDomainText( ( idp.domain_mapping || [] ).join( ', ' ) );
			onEditorChanged?.( idp );
		},
		[ onEditorChanged ]
	);

	const startEdit = useCallback(
		async ( id, errorMessage ) => {
			try {
				const idp = await apiFetch( {
					path: `${ endpointBase }/${ id }`,
				} );
				openEditor( idp );
			} catch {
				showToast( errorMessage, 'error' );
			}
		},
		[ endpointBase, openEditor, showToast ]
	);

	const startNew = useCallback( () => {
		openEditor( { ...emptyIdp } );
	}, [ openEditor, emptyIdp ] );

	const cancelEdit = useCallback( () => {
		setEditing( null );
		setRoleMappings( [] );
		setDomainText( '' );
		onEditorChanged?.( null );
	}, [ onEditorChanged ] );

	const updateField = useCallback( ( key, value ) => {
		setEditing( ( prev ) => ( { ...prev, [ key ]: value } ) );
	}, [] );

	const updateRoleMapping = useCallback( ( idx, field, value ) => {
		setRoleMappings( ( prev ) => {
			const next = [ ...prev ];
			next[ idx ] = { ...next[ idx ], [ field ]: value };
			return next;
		} );
	}, [] );

	const removeRoleMapping = useCallback( ( idx ) => {
		setRoleMappings( ( prev ) => prev.filter( ( _, i ) => i !== idx ) );
	}, [] );

	const addRoleMapping = useCallback( () => {
		setRoleMappings( ( prev ) => [
			...prev,
			{ group: '', role: 'subscriber' },
		] );
	}, [] );

	const handleDelete = useCallback(
		async ( id ) => {
			try {
				await apiFetch( {
					path: `${ endpointBase }/${ id }`,
					method: 'DELETE',
				} );
				showToast( 'IdP deleted.' );
				loadIdps();
			} catch {
				showToast( 'Failed to delete IdP.', 'error' );
			}
		},
		[ endpointBase, showToast, loadIdps ]
	);

	return {
		idps,
		loaded,
		editing,
		roleMappings,
		domainText,
		setDomainText,
		loadIdps,
		startEdit,
		startNew,
		cancelEdit,
		updateField,
		updateRoleMapping,
		removeRoleMapping,
		addRoleMapping,
		handleDelete,
	};
}

export function buildIdpPayload( editing, roleMappings, domainText ) {
	const role_mapping = {};
	roleMappings.forEach( ( { group, role } ) => {
		const g = group.trim();
		if ( g ) {
			role_mapping[ g ] = role;
		}
	} );

	const domain_mapping = domainText
		.split( ',' )
		.map( ( d ) => d.trim().toLowerCase() )
		.filter( Boolean );

	return {
		...editing,
		role_mapping,
		domain_mapping,
	};
}
