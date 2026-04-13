/**
 * Enterprise Auth – Identity-first login flow for wp-login.php
 *
 * Step 1: User enters email → route-login API checks domain.
 *   - If SSO: redirect to external IdP.
 *   - If local: reveal password form + Passkey button (Step 2).
 * Step 2: Password form (native WP) and/or WebAuthn ceremony.
 */
import './passkey-login.css';

( function () {
	'use strict';

	var config = window.eaPasskeyLogin || {};
	var inStep1 = true;

	// ── Helpers ──────────────────────────────────────────────────────────

	function bufferToBase64url( buffer ) {
		var bytes = new Uint8Array( buffer );
		var binary = '';
		for ( var i = 0; i < bytes.length; i++ ) {
			binary += String.fromCharCode( bytes[ i ] );
		}
		return btoa( binary )
			.replace( /\+/g, '-' )
			.replace( /\//g, '_' )
			.replace( /=+$/g, '' );
	}

	function base64urlToBuffer( str ) {
		var base64 = str.replace( /-/g, '+' ).replace( /_/g, '/' );
		var padded = base64 + '='.repeat( ( 4 - ( base64.length % 4 ) ) % 4 );
		var binary = atob( padded );
		var bytes = new Uint8Array( binary.length );
		for ( var i = 0; i < binary.length; i++ ) {
			bytes[ i ] = binary.charCodeAt( i );
		}
		return bytes.buffer;
	}

	function setStatus( elId, msg, isError ) {
		var el = document.getElementById( elId );
		if ( el ) {
			el.textContent = msg;
			el.style.color = isError ? '#d63638' : '#00a32a';
		}
	}

	function doFetch( path, opts ) {
		opts = opts || {};
		opts.headers = opts.headers || {};
		opts.headers[ 'X-WP-Nonce' ] = config.nonce;
		if ( ! opts.headers[ 'Content-Type' ] && opts.method === 'POST' ) {
			opts.headers[ 'Content-Type' ] = 'application/json';
		}
		return fetch( config.restUrl + path, opts ).then( function ( res ) {
			return res.json();
		} );
	}

	function currentRedirectTarget() {
		var params = new URLSearchParams( window.location.search );
		return params.get( 'redirect_to' ) || '';
	}

	function clearLocalFlowQuery() {
		var url = new URL( window.location.href );
		if ( ! url.searchParams.has( 'ea_local_flow' ) ) {
			return;
		}

		url.searchParams.delete( 'ea_local_flow' );
		window.history.replaceState( {}, document.title, url.toString() );
	}

	// ── DOM references ──────────────────────────────────────────────────

	var form, userLogin, userLabel;
	var passWrap, forgetMe, submitP;
	var stepContinue, stepPasskey, backLink;

	function cacheDom() {
		form         = document.getElementById( 'loginform' );
		userLogin    = document.getElementById( 'user_login' );
		userLabel    = form ? form.querySelector( 'label[for="user_login"]' ) : null;
		// WP 6.x uses .user-pass-wrap; older versions use .login-password
		passWrap     = document.querySelector( '.user-pass-wrap' )
		            || document.querySelector( '.login-password' );
		forgetMe     = document.querySelector( '.forgetmenot' );
		submitP      = form ? form.querySelector( 'p.submit' ) : null;
		stepContinue = document.getElementById( 'ea-step-continue' );
		stepPasskey  = document.getElementById( 'ea-step-passkey' );
		backLink     = document.getElementById( 'ea-back-link' );
	}

	// ── Step transitions ────────────────────────────────────────────────

	var step2Els; // password, remember-me, submit

	function setupStep1() {
		if ( ! form || ! userLogin ) {
			return;
		}

		// Relabel the WP username field as "Email Address"
		if ( userLabel ) {
			userLabel.textContent = 'Email Address';
		}
		userLogin.setAttribute( 'placeholder', 'you@company.com' );
		userLogin.setAttribute( 'type', 'email' );

		// Collect step-2 elements
		step2Els = [ passWrap, forgetMe, submitP ].filter( Boolean );

		// Intercept form submit in step 1 so Enter key triggers our routing
		form.addEventListener( 'submit', function ( e ) {
			if ( inStep1 ) {
				e.preventDefault();
				var routeBtn = document.getElementById( 'ea-route-btn' );
				if ( routeBtn ) {
					routeBtn.click();
				}
			}
		} );
	}

	function transitionToStep2( email ) {
		inStep1 = false;

		// Hide Continue, show password/submit/passkey
		if ( stepContinue ) {
			stepContinue.style.display = 'none';
		}
		step2Els.forEach( function ( el ) {
			el.style.display = 'block';
		} );

		// Reorder: move remember-me and Log In button above the passkey
		// section so the layout is: password → login → divider → passkey.
		if ( stepPasskey ) {
			[ forgetMe, submitP ].forEach( function ( el ) {
				if ( el && el.parentNode ) {
					el.parentNode.insertBefore( el, stepPasskey );
				}
			} );
		}

		// Show passkey button (only if WebAuthn is supported)
		if ( stepPasskey && window.PublicKeyCredential ) {
			stepPasskey.style.display = '';
		}
		if ( backLink ) {
			backLink.style.display = '';
		}

		// Ensure email is in the username field and focus password
		userLogin.value = email;
		var passField = document.getElementById( 'user_pass' );
		if ( passField ) {
			passField.disabled = false;
			passField.focus();
		}
	}

	function transitionToStep1() {
		inStep1 = true;

		// Show Continue, hide password/submit/passkey
		if ( stepContinue ) {
			stepContinue.style.display = '';
		}
		step2Els.forEach( function ( el ) {
			el.style.display = 'none';
		} );
		if ( stepPasskey ) {
			stepPasskey.style.display = 'none';
		}
		if ( backLink ) {
			backLink.style.display = 'none';
		}

		setStatus( 'ea-route-status', '', false );
		var routeBtn = document.getElementById( 'ea-route-btn' );
		if ( routeBtn ) {
			routeBtn.disabled = false;
		}
		userLogin.value = '';
		userLogin.focus();
	}

	// ── Step 1: Email routing ───────────────────────────────────────────

	function initRouting() {
		var routeBtn = document.getElementById( 'ea-route-btn' );
		if ( ! routeBtn || ! userLogin ) {
			return;
		}

		routeBtn.addEventListener( 'click', function () {
			var email = userLogin.value.trim();

			if ( ! email ) {
				setStatus( 'ea-route-status', 'Please enter your email address.', true );
				return;
			}

			routeBtn.disabled = true;
			setStatus( 'ea-route-status', 'Checking…', false );

			doFetch( 'route-login', {
				method: 'POST',
				body: JSON.stringify( {
					email: email,
					redirect_to: currentRedirectTarget(),
				} ),
			} )
			.then( function ( data ) {
				if ( data.error ) {
					throw new Error( data.error );
				}

				if ( ! data.redirect_url ) {
					throw new Error( 'Could not continue login. Please try again.' );
				}

				setStatus( 'ea-route-status', 'Continuing…', false );
				window.location.href = data.redirect_url;
			} )
			.catch( function ( err ) {
				setStatus( 'ea-route-status', err.message || 'Routing failed.', true );
				routeBtn.disabled = false;
			} );
		} );

		// Back button
		var backBtn = document.getElementById( 'ea-back-btn' );
		if ( backBtn ) {
			backBtn.addEventListener( 'click', function ( e ) {
				e.preventDefault();
				transitionToStep1();
			} );
		}
	}

	function resumeLocalFlow() {
		var params = new URLSearchParams( window.location.search );
		var flow = params.get( 'ea_local_flow' );

		if ( ! flow || ! userLogin ) {
			return;
		}

		setStatus( 'ea-route-status', 'Continuing…', false );

		doFetch( 'route-login/local-options?flow=' + encodeURIComponent( flow ) )
			.then( function ( data ) {
				if ( data.error ) {
					throw new Error( data.error );
				}

				if ( ! data.email ) {
					throw new Error( 'Login step expired. Please enter your email again.' );
				}

				transitionToStep2( data.email );
				setStatus( 'ea-route-status', '', false );
				clearLocalFlowQuery();
			} )
			.catch( function ( err ) {
				clearLocalFlowQuery();
				setStatus(
					'ea-route-status',
					err.message || 'Login step expired. Please enter your email again.',
					true
				);
			} );
	}

	// ── Step 2: Passkey authentication ──────────────────────────────────

	function initPasskey() {
		var btn = document.getElementById( 'ea-passkey-login-btn' );
		if ( ! btn ) {
			return;
		}

		// Hide passkey button if WebAuthn is not supported.
		if ( ! window.PublicKeyCredential ) {
			btn.style.display = 'none';
			return;
		}

		btn.addEventListener( 'click', function () {
			btn.disabled = true;
			setStatus( 'ea-passkey-status', 'Waiting for passkey…', false );

			var email = ( userLogin && userLogin.value ) || '';
			var params = [];
			var redirectTo = getQueryParam( 'redirect_to' );

			if ( email ) {
				params.push( 'email=' + encodeURIComponent( email ) );
			}

			if ( redirectTo ) {
				params.push( 'redirect_to=' + encodeURIComponent( redirectTo ) );
			}

			var queryParams = params.length ? '?' + params.join( '&' ) : '';

			doFetch( 'passkeys/login' + queryParams )
				.then( function ( options ) {
					if ( options.error ) {
						throw new Error( options.error );
					}

					var sessionKey = options.session_key;

					var publicKey = {
						challenge: base64urlToBuffer( options.challenge ),
						rpId: options.rpId,
						timeout: options.timeout,
						userVerification: options.userVerification || 'preferred',
					};

					if (
						options.allowCredentials &&
						options.allowCredentials.length > 0
					) {
						publicKey.allowCredentials =
							options.allowCredentials.map( function ( cred ) {
								return {
									type: cred.type,
									id: base64urlToBuffer( cred.id ),
									transports: cred.transports || [],
								};
							} );
					}

					return navigator.credentials
						.get( { publicKey: publicKey } )
						.then( function ( credential ) {
							return { credential: credential, sessionKey: sessionKey };
						} );
				} )
				.then( function ( ctx ) {
					var credential = ctx.credential;
					var payload = {
						id: credential.id,
						rawId: bufferToBase64url( credential.rawId ),
						type: credential.type,
						response: {
							clientDataJSON: bufferToBase64url(
								credential.response.clientDataJSON
							),
							authenticatorData: bufferToBase64url(
								credential.response.authenticatorData
							),
							signature: bufferToBase64url(
								credential.response.signature
							),
						},
						session_key: ctx.sessionKey,
					};

					if ( credential.response.userHandle ) {
						payload.response.userHandle = bufferToBase64url(
							credential.response.userHandle
						);
					}

					return doFetch( 'passkeys/login', {
						method: 'POST',
						body: JSON.stringify( payload ),
					} );
				} )
				.then( function ( result ) {
					if ( result.success ) {
						setStatus( 'ea-passkey-status', 'Success! Redirecting…', false );
						window.location.href =
							result.redirect_to || '/wp-admin/';
					} else {
						setStatus( 'ea-passkey-status', result.error || 'Login failed.', true );
						btn.disabled = false;
					}
				} )
				.catch( function ( err ) {
					if ( err.name === 'NotAllowedError' ) {
						setStatus( 'ea-passkey-status', 'Passkey login was cancelled.', true );
					} else {
						setStatus( 'ea-passkey-status', err.message || 'Login failed.', true );
					}
					btn.disabled = false;
				} );
		} );
	}

	function getQueryParam( key ) {
		var params = new URLSearchParams( window.location.search );
		return params.get( key ) || '';
	}

	// ── Boot ────────────────────────────────────────────────────────────

	document.addEventListener( 'DOMContentLoaded', function () {
		cacheDom();
		setupStep1();
		initRouting();
		initPasskey();
		resumeLocalFlow();
	} );
} )();
