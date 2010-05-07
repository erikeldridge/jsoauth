// The standard js lib is here: http://oauth.googlecode.com/svn/code/javascript/oauth.js
// I put this script together as a learning exercise
// License: anything not credited to someone else is licensed under Yahoo! BSD: http://gist.github.com/375593

var jsoauth = (function() {
    
	//@credit "JavaScript: The Good Stuff", Crockford
	var parseURL = function(inputURL) {

		var pattern = "^(https|http):\/\/" //scheme
		+ "([0-9a-z\-.]+)" //authority, aka host
		+ "(?::(\\d+))?" //port, optional
		+ "(?:\/([0-9a-z\-_\/]+))" //path
		+ "(?:[?]([0-9a-z=]*))?" //query, optional. the ?:[?] is used because ?:\? causes problems in FF3,safari
		+ "(?:#(.*))?",
			//anchor, optional
		regex = new RegExp(pattern),
			matches = regex.exec(inputURL.toLowerCase()),
			fields = ['url', 'scheme', 'authority', 'port', 'path', 'query', 'anchor'],
			parsedURL = {};

		if (!matches) {
			throw ("parseURL error: incorrect formatting. Expected http[s]://host.tld[:port]/path[?q=query][#anchor], but got " + inputURL);
		}

		//map matched items to field names
		for (var i = 0; i < fields.length; i++) {
			parsedURL[fields[i]] = matches[i];
		}

		return parsedURL;
	},

	// @credit oauth js lib: http://code.google.com/p/oauth/source/browse/#svn/code/javascript
	percentEncode = function(str) {

		if (str == null) {
			return "";
		}

		str = encodeURIComponent(str);
		// Now replace the values which urlencodeComponent doesn't do
		// urlencodeComponent ignores: - _ . ! ~ * ' ( )
		// OAuth dictates the only ones you can ignore are: - _ . ~
		// Source: http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Global_Functions:urlencodeComponent
		str = str.replace("!", "%21", "g");
		str = str.replace("*", "%2A", "g");
		str = str.replace("'", "%27", "g");
		str = str.replace("(", "%28", "g");
		str = str.replace(")", "%29", "g");

		return str;
	},

	// @ref http://oauth.net/core/1.0/#rfc.section.9.1.2
	constructReqURL = function(inputURL) {

		var parsedURL;

		try {

			parsedURL = parseURL(inputURL);
			return parsedURL['scheme'] + '://' + parsedURL['authority'] + '/' + parsedURL['path'];

		} catch(e) {
			//incorrectly formatted input url
			alert(e);
		}
	},

	// @pre params already collected & sorted
	// @ref http://oauth.net/core/1.0/#rfc.section.9.1.1
	concatenateParams = function(params) {
		return params.join("&");
	},

	// @ref http://oauth.net/core/1.0/#rfc.section.9.1.1
	// @ref http://oauth.net/core/1.0/#rfc.section.A.5.1
	normalizeReqParams = function(params) {

		params = params.sort();
		params = concatenateParams(params);
		params = percentEncode(params);

		return params;
	},

	// @ref http://oauth.net/core/1.0/#rfc.section.9.1.3
	concatenateReqElems = function(args) {
		return args.reqMethod + '&' + args.reqURL + '&' + args.params;
	},

	// @credit http://kentbrewster.com/oauth-baby-steps/
	// nonce is just a unique string
	createNonce = function() {

		var nonce = '';

		for (var i = 0; i < 10; i++) {
			nonce += String.fromCharCode(Math.floor(Math.random() * 26) + 97);
		}

		return nonce;
	},

	// @ref http://oauth.net/core/1.0/#rfc.section.9.2
	generateSig = function(args) {

		var text = args.baseStr;
		var key = percentEncode(args.secret) + '&' + percentEncode(args.token);
		var raw_signature = Crypto.HMAC(Crypto.SHA1, text, key, {
			asBytes: true
		});
		var sig = Crypto.util.bytesToBase64(raw_signature);
		return sig;
	};

	return {
		consumerKey: '',
		consumerSecret: '',
		reqMethod: 'GET',
		
		//must be uppercase @ref http://oauth.net/core/1.0/#rfc.section.9.1.3
		sigMethod: 'HMAC-SHA1',
		
		oauthVersion: '1.0',
		callbackURL: '',
		
		//handy for debugging
        params: null,
        normalReqParams: null,
        baseStr: null,
        signature: null,
        
		sign: function(args) {

			var timestamp = Math.floor(new Date().getTime() / 1000);
			
			    // flush so multiple calls to obj don't conflict
				this.normalReqParams = null;
				this.baseStr = null; 
				this.signature = null; 
				this.params = [];

			// basic oauth params formatted as strings in array so we can sort easily
			this.params.push('oauth_consumer_key=' + this.consumerKey);
			this.params.push('oauth_nonce=' + createNonce());
			this.params.push('oauth_signature_method=' + this.sigMethod);
			this.params.push('oauth_timestamp=' + timestamp);
			this.params.push('oauth_version=' + this.oauthVersion);
			this.params.push('oauth_callback=' + percentEncode(this.callbackURL));

			// if params passed in (as array of 'key=val' strings), add them
			if (args.params) {
				for (var i = 0; i < args.params.length; i++) {
					this.params.push(args.params[i]);
				}
			}

			// elems for base str
			this.normalReqParams = normalizeReqParams(this.params);
			reqURL = constructReqURL(args.URL);

			// create base str
			this.baseStr = concatenateReqElems({
				'reqMethod': this.reqMethod,
				'reqURL': percentEncode(reqURL),
				'params': this.normalReqParams
			});
            
			this.signature = generateSig({
				'baseStr': this.baseStr,
				'secret': this.consumerSecret,
				'token': ''
			});

			this.params.push('oauth_signature=' + percentEncode(this.signature));

			//maintain correct alpha sort - very important as it affects the signature
			//@ref http://oauth.net/core/1.0/#rfc.section.9.1.1	
			//@ref http://oauth.net/core/1.0/#9.2.1
			var signedURL = args.URL + '?' + concatenateParams(this.params.sort());

			return signedURL;
		}
	};
}());
