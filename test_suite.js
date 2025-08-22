import * as jose from "https://cdn.jsdelivr.net/npm/jose@latest/+esm";
console.log(jose)
//const jwt = require('./node_modules/jsonwebtoken');
//const process = require('process')
// const jose = require('node-jose');
// const pricess = require('./node_modules/process');
// const { JSDOM } = require('./node_modules/jsdom');

// Load your HTML file

// const htmlContent = readFileSync('./index.html', 'utf8');
// const dom = new JSDOM(htmlContent, {
//     url: `file://${__dirname}/index.html`,
//     runScripts: "dangerously",
//     resources: "usable"
//   });
// const document = dom.window.document;
// function waitForLoad(domInstance, callback) {
//     domInstance.window.document.addEventListener("DOMContentLoaded", callback);
//   }
function encodeTokenNPM(header, payload, secretKey) {
    // Header und Payload zu Base64Url encodieren
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    
    // Token ohne Signatur erstellen
    const unsignedToken = `${encodedHeader}.${encodedPayload}`;

    // Signatur erstellen
    const signature = jwt.sign(payload, secretKey, { header, algorithm: header.alg }).split('.')[2];

    // Finales Token zusammenbauen
    const token = `${unsignedToken}.${signature}`;
    
    console.log("🔐 Generierter Token:", token);
    return token;
}

// Beispielaufruf
function printTestSummary() {
    console.log("\n==================== TEST SUMMARY ====================");
    console.log(`Total Tests: ${testCount}`);
    console.log(`✅ Passed: ${passedCount}`);
    console.log(`❌ Failed: ${failedCount}`);
    console.log("=====================================================");
}
async function verifyTokenTest(token, secretKeyOrPublicKey, algorithm) {
    try {
        let k;
        
        // Symmetrischer Algorithmus (HS256, HS384, HS512)
        if (algorithm === 'HS256' || algorithm === 'HS384' || algorithm === 'HS512') {
            const jwk = {
                "kty": "oct",
                "k": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                "alg": algorithm
              };
            const kl = await jose.JWK.asKey(jwk);  // 'oct' steht für HMAC (HS)
            const keystore = jose.JWK.createKeyStore();
            k = await keystore.add(kl);

        // Asymmetrischer Algorithmus (RS256, RS384, RS512)
        } else if (algorithm === 'RS256' || algorithm === 'RS384' || algorithm === 'RS512') {
            k = await jose.JWK.asKey(secretKeyOrPublicKey, 'RSA');  // RSA-Schlüssel (öffentlicher Schlüssel)

        // Asymmetrischer Algorithmus (ES256, ES384, ES512)
        } else if (algorithm === 'ES256' || algorithm === 'ES384' || algorithm === 'ES512') {
            k = await jose.JWK.asKey(secretKeyOrPublicKey, 'EC');  // EC-Schlüssel (ECDSA)

        // Asymmetrischer Algorithmus (PS256, PS384, PS512) - RSA-PSS
        } else if (algorithm === 'PS256' || algorithm === 'PS384' || algorithm === 'PS512') {
            k = await jose.JWK.asKey(secretKeyOrPublicKey, 'RSA-PSS');  // RSA-PSS-Schlüssel
        } else {
            throw new Error(`Algorithmus ${algorithm} wird nicht unterstützt`);
        }

        // Verifizieren des Tokens
        const decoded = await jose.JWS.createVerify(k).verify(token);

        console.log("✅ Token ist gültig:", JSON.parse(decoded.payload));
        return JSON.parse(decoded.payload);  // Hier bekommst du das dekodierte Payload zurück
    } catch (error) {
        console.error("❌ Ungültiger Token:", error.message);
        return null;
    }
}
// Tests

let testCount = 0;
let passedCount = 0;
let failedCount = 0;
async function test(description, callback) {
    testCount++;    
    try {
        await callback();
        console.info(`✅ ${testCount}: ${description}`);
        passedCount++;
    } catch (error) {
        failedCount++;
        console.error(`❌ ${testCount}: ${description}`);
        console.error(error);
    }
}
function sanityTests(){
    test('Check if encoding works correctly', () => {
        document.getElementById("decodedHeader").value = '{"alg": "none","typ": "JWT"}';
        document.getElementById("decodedBody").value = '{"sub": "1234567890","name": "John Doe","admin": true,"iat": 1516239022}';
        document.getElementById("algorithm").value = "none";
        encodeToken();
        const token = document.getElementById("token").value 
        if (token !== "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.") {
            throw new Error('Encoding is not working');
        }
    });
}
async function signatureTests(){
    const response = await fetch("./jwt_test_cases.json");
    const testCases = await response.json();
    
    // -------------------------- Statische Tests --------------------------
    prettyPrintCenter("Static Tests");
    sanityTests();

    for (var i = 0; i < testCases.length;i++){
        await test(`Check if ${testCases[i]["header"]["alg"]} works correctly`, async () => {
            
            document.getElementById("decodedHeader").value = JSON.stringify(testCases[i]["header"]);
            document.getElementById("decodedBody").value = JSON.stringify(testCases[i]["body"]);
            document.getElementById("algorithm").value = testCases[i]["header"]["alg"];
            document.getElementById("key").value = testCases[i]["key"];
            document.getElementById("privateKey").value = testCases[i]["key"];
            await encodeToken();
            let token = document.getElementById("token").value 
            if (token !== testCases[i]["token"]) {
    
                throw new Error(`${testCases[i]["header"]["alg"]} is not working\nExpected: ${testCases[i]["token"]}\nBut got:  ${token}\n`);
            }
        });
    }
    // -------------------------- Tests versus jose --------------------------
    document.getElementById('decodedBody').value = JSON.stringify({"sub":"1234567890","name":"Max Mustermann","iat": Math.floor(Date.now() / 1000)-100,"exp": Math.floor(Date.now() / 1000)+100})
    prettyPrintCenter("versus jose")

    const algs = ["HS256","HS384","HS512","PS256","PS384","PS512","RS256","RS384","RS512","ES256","ES384","ES512"];
    for (let i = 0; i < algs.length; i++){
        document.getElementById("algorithm").value = algs[i]
        changeAlgorithmEvent();
        await encodeToken();
        const k = algs[i][0] === 'H' ? new TextEncoder().encode(document.getElementById("key").value) : await jose.importSPKI(document.getElementById('publicKey').value,algs[i]); 
        await test(`Check if ${algs[i]} signature is correct`,async () => await jose.jwtVerify(document.getElementById("token").value,k));
        await test(`Check if verification is correct aswell`,async () => {
            if (await verifySignature() !== true) throw new Error(`${algs[i]}: Signature should be valid`)
    })
    }
}
/*
async function encryptionTests(toBeTested = 0) {
    prettyPrintCenter("Encryption Tests");

    // Fetch the JSON data from the specified URL
    const response = await fetch('./jwe_test_tokens.json'); // Update the path to your JSON file
    const data = await response.json();

    const cek_algs = ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"];
    const algs = [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", 
        "A128KW", "A192KW", "A256KW", 
        "dir", "ECDH-ES", 
        "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", 
        "A128GCMKW", "A192GCMKW", "A256GCMKW", 
        "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"
    ];

    // Iterate through each algorithm
    for (let alg of algs) {
        // Determine the appropriate private key based on the algorithm
        let privateKey;
        // TODO RSA1_5 missing test cases #
        if (toBeTested && !(alg.startsWith(toBeTested))){ //TODO Single 
            continue; 
        }
        if (alg.startsWith("RSA")) {
            privateKey = data.keys.RSA.private_pem; // Use RSA private key for RSA algorithms
            document.getElementById("privateKeyJWE").value = privateKey;
        } else if (alg.startsWith("ECDH")) {
            privateKey = data.keys.ECDH.private_pem; // Use ECDH private key for ECDH algorithms
            document.getElementById("privateKeyJWE").value = privateKey;
            console.warn(alg, "Test not Implemented")
            continue
        } 
        else if (alg.startsWith("A")){
            // Handle symmetric key algorithms or other cases if necessary
            
            document.getElementById("keyJWE").value = data.keys[alg.slice(0,4)].jwk.k;
        }
        else if (alg.startsWith("PBES2")){
            console.warn(alg,"Test not Implemented")
            continue
        }
        else if (alg === "dir"){
            console.warn(alg, "Test not Implemented")
            continue
        }

        // Iterate through each content encryption key algorithm
        for (let cek_alg of cek_algs) {
            document.getElementById("decodedBodyJWE").value = "";
            var body = "";
            console.log(`Testing algorithm: ${alg}, CEK algorithm: ${cek_alg}`);

            // Set the algorithm and encryption algorithm in the UI
            document.getElementById("algorithmJWE").value = alg;
            document.getElementById("encryptionAlgorithmJWE").value = cek_alg;

            // Construct the token key based on the current algorithm and CEK algorithm
            const tokenKey = `${alg}-${cek_alg}`;
            const token = data.encrypted_tokens[tokenKey];

            // Check if the token exists
            if (!token) {
                console.warn(`No token found for ${tokenKey}`);
                continue
            }

            // Set the token in the UI
            document.getElementById("tokenJWE").value = token;
            

            try {
                // Attempt to decrypt the token
                await decrypt();
                body = JSON.stringify(JSON.parse(document.getElementById("decodedBodyJWE").value));
            } catch (error) {
                console.error(`Decryption failed for ${tokenKey}:`, error);
                // Skip to the next test case on error
            }

            // Validate the decrypted body against the expected body
            await test(`${alg}-${cek_alg}: Check if token gets decrypted correctly`, async () => {
                const expectedBody = JSON.stringify(JSON.parse(data.verified_tokens[tokenKey]));
                if (body !== expectedBody) {
                    throw new Error(`${alg}-${cek_alg}: Does not get decrypted correctly\n Expected ${expectedBody}\nGot ${body}`);
                }
            });
        }
    }
}
*/

async function encryptionTests(algorithmToBeTested = "all", encryptionAlgorithmToBeTested = "all") {
    const algs = ["A128KW", "A192KW", "A256KW",
        "RSA-OAEP","RSA-OAEP-256","dir",
        "A128GCMKW", "A192GCMKW", "A256GCMKW",
        "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"
    ]; 
    const encryptionAlgs = ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"];
    
    prettyPrintCenter("Encryption Tests");
    let tested_algorithms = [];
    let tested_encryption_algorithms = [];
    for (const alg of algs) {
        for (const enc of encryptionAlgs) {
            if (algorithmToBeTested !== "all" && alg !== algorithmToBeTested) {
                continue; // Skip if the algorithm does not match the specified one
            }
            if (encryptionAlgorithmToBeTested !== "all") {
                if (encryptionAlgorithmToBeTested === "CBC" && !enc.includes("CBC")) continue;
                if (encryptionAlgorithmToBeTested === "GCM" && !enc.includes("GCM")) continue;
                if (encryptionAlgorithmToBeTested !== "CBC" && encryptionAlgorithmToBeTested !== "GCM" && enc !== encryptionAlgorithmToBeTested) continue;
            }
            tested_algorithms.push(alg);
            tested_encryption_algorithms.push(enc);

            console.info(`------- Testing algorithm: ${alg}, CEK algorithm: ${enc}`);
            
            
            const payload = { "sub": "1234567890", "name": "Max Mustermann", "iat": Math.floor(Date.now() / 1000) - 100, "exp": Math.floor(Date.now() / 1000) + 100 };
            let protectedHeader_jose = { alg, enc };
            
            
            document.getElementById("algorithmJWE").value = alg;
            document.getElementById("encryptionAlgorithmJWE").value = enc;
            changeEncryptionAlgorithmEvent();
            changeAlgorithmEvent();
            document.getElementById("decodedBodyJWE").value = JSON.stringify(payload);
            const token_field = document.getElementById("tokenJWE");
            document.getElementById("keyJWE").value = "";
            document.getElementById("publicKeyJWE").value = "";
            document.getElementById("privateKeyJWE").value = "";

            // PBES2: Setze Salt und Iterationen
            if (alg.startsWith("PBES2")) {
                const salt = window.crypto.getRandomValues(new Uint8Array(16));
                const salt_b64url = Uint8ArrayTobase64Url(salt);
                document.getElementById("saltJWE").value = URL_to_base64(salt_b64url);
                document.getElementById("pbkdf2IterationsJWE").value = 4096;
            }
            
            await encrypt();
            
            let key_decryption =""
            let key_encryption = ""
            let jwe_jose = "";
            let plaintext_jose = "";
            let jwe_meiner = "";
            let jwk_pub = {};
            let jwk_priv = {};
            if (alg.startsWith("A")){
                jwk_pub = {
                    kty: "oct",
                    k: base64_to_URL(document.getElementById("keyJWE").value), 
                    alg: alg
                };
                jwk_priv = {
                    "kty": "oct",
                    k: base64_to_URL(document.getElementById("keyJWE").value), 
                    alg: alg
                };
            }
            else if (alg === "RSA1_5" || alg === "RSA-OAEP" || alg === "RSA-OAEP-256") {
                jwk_pub = await pemToJwk(document.getElementById("publicKeyJWE").value);
                jwk_priv = await pemToJwk(document.getElementById("privateKeyJWE").value);
            }
            else if (alg === "dir") {
                jwk_pub = {
                    kty: "oct",
                    k: base64_to_URL(document.getElementById("keyJWE").value), 
                    alg: alg
                };
                jwk_priv = {
                    kty: "oct",
                    k: base64_to_URL(document.getElementById("keyJWE").value), 
                    alg: alg
                };
            }
            else if (alg.startsWith("PBES2")) {
            }
            else {
                throw new Error(`Algorithm ${alg} is not supported in this test suite\n Viel Spaß Beim Schlüssel importieren :)\n`);
            }
            if (alg !== "dir" && !alg.startsWith("PBES2")) {
                key_decryption = await jose.importJWK(jwk_priv, alg)
                key_encryption = await jose.importJWK(jwk_pub, alg)
                jwe_jose = await new jose.CompactEncrypt(
                    new TextEncoder().encode(JSON.stringify(payload)))
                    .setProtectedHeader(protectedHeader_jose)
                    .encrypt(key_encryption);
                jwe_meiner = document.getElementById("tokenJWE").value;
                plaintext_jose = await jose.compactDecrypt(jwe_jose, key_decryption);
            }
            else if (alg === "dir") {
                key_decryption = await jose.importJWK(jwk_priv, enc);
                key_encryption = await jose.importJWK(jwk_pub, enc);
                jwe_jose = await new jose.CompactEncrypt(
                    new TextEncoder().encode(JSON.stringify(payload)))
                    .setProtectedHeader(protectedHeader_jose)
                    .encrypt(key_encryption);
                jwe_meiner = document.getElementById("tokenJWE").value;
                plaintext_jose = await jose.compactDecrypt(jwe_jose, key_decryption);
            }
            else if (alg.startsWith("PBES2")) {
                key_encryption = new TextEncoder().encode(document.getElementById("keyJWE").value);
                key_decryption = new TextEncoder().encode(document.getElementById("keyJWE").value);
                const temp_header = JSON.parse(document.getElementById("decodedHeaderJWE").value)
                protectedHeader_jose = {
                    alg: alg,
                    enc: enc,
                    p2s: temp_header.p2s, // Salt
                    p2c: temp_header.p2c // Iterations
                }
            }
            //* Tests
            // 1. Can my token be decrypted via jose?
            // 2. Is the payload the same when my token is decrypted via jose?
            // 3. Can my token be decrypted via my implementation?
            // 4. Is the payload the same when my token is decrypted via my implementation?
            // 5. Can the jose token be decrypted via my implementation?
            // 6. Is the payload the same when the jose token is decrypted via my implementation?
            
            // 1. Can my token be decrypted via jose?
            await test (`${alg}-${enc} Encryption Test: Check if my token can be decrypted via jose`, async () => {
                const decrypted = await jose.compactDecrypt(jwe_meiner, key_decryption);
            });
            // 2. Is the payload the same when my token is decrypted via jose?
            await test (`${alg}-${enc} Encryption Test: Check if payload is the same when my token is decrypted via jose`, async () => {
                const decrypted = b64URLdecode(Uint8ArrayTobase64Url((await jose.compactDecrypt(jwe_meiner, key_decryption)).plaintext));
                if (JSON.stringify(JSON.parse(decrypted)) !== JSON.stringify(payload)) {
                    throw new Error(`${alg}-${enc}: Decryption failed\nExpected: ${JSON.stringify(payload)}\nGot: ${JSON.stringify(JSON.parse(decrypted))}`);
                }
            });
            // 3. Can my token be decrypted via my implementation?
            await test(`${alg}-${enc} Encryption Test: Check if my token can be decrypted via my implementation`, async () => {
                token_field.value = jwe_meiner;
                if (!(await decrypt())){
                    throw new Error(`${alg}-${enc}: Decryption failed`);
                }
            });
            document.getElementById("decodedBodyJWE").value = "";
            document.getElementById("decodedHeaderJWE").value = "";
            // 4. Is the payload the same when my token is decrypted via my implementation?
            await test(`${alg}-${enc} Encryption Test: Check if payload is the same when my token is decrypted via my implementation`, async () => {
                token_field.value = jwe_meiner;

                await decrypt();
                if (JSON.stringify(JSON.parse(document.getElementById("decodedBodyJWE").value)) !== JSON.stringify(payload)) {
                    throw new Error(`${alg}-${enc}: Decryption failed\nExpected: ${JSON.stringify(payload)}\nGot: ${JSON.stringify(JSON.parse(document.getElementById("decodedBodyJWE").value))}`);
                }
            });
            // 5. Can the jose token be decrypted via my implementation?
            document.getElementById("decodedBodyJWE").value = "";
            document.getElementById("decodedHeaderJWE").value = "";
            await test(`${alg}-${enc} Encryption Test: Check if jose token can be decrypted via my implementation`, async () => {
                token_field.value = jwe_jose;
                await decrypt();
                if (!(await decrypt())){
                    throw new Error(`${alg}-${enc}: Decryption failed`);
                }
            });
            document.getElementById("decodedBodyJWE").value = "";
            document.getElementById("decodedHeaderJWE").value = "";
            // 6. Is the payload the same when the jose token is decrypted via my implementation?
            await test(`${alg}-${enc} Encryption Test: Check if payload is the same when jose token is decrypted via my implementation`, async () => {
                token_field.value = jwe_jose;
                await decrypt();
                if (JSON.stringify(JSON.parse(document.getElementById("decodedBodyJWE").value)) !== JSON.stringify(payload)) {
                    throw new Error(`${alg}-${enc}: Decryption failed\nExpected: ${JSON.stringify(payload)}\nGot: ${JSON.stringify(JSON.parse(document.getElementById("decodedBodyJWE").value))}`);
                }
            });
    
        }
        
    }
    return {
            testedAlgorithms : [... new Set(tested_algorithms)],
            testedEncryptionAlgorithms : [... new Set(tested_encryption_algorithms)]
        };


        
}
async function runEncryptionTests(algorithmToBeTested = "all", encryptionAlgorithmToBeTested = "all"){
    testCount = 0;
    passedCount = 0;
    failedCount = 0;
    prettyPrintTitle("Test-Suite");
    prettyPrintTitle("Encryption-Tests");
    const tested_algs = await encryptionTests(algorithmToBeTested, encryptionAlgorithmToBeTested);
    prettyPrintCenter('All tests completed.');
    console.log(`Tested Algorithms: ${tested_algs.testedAlgorithms.join(", ")}`);
    console.log(`Tested Encryption Algorithms: ${tested_algs.testedEncryptionAlgorithms.join(", ")}`);
    printTestSummary();
}

async function runAllTests(){
    testCount = 0;
    passedCount = 0;
    failedCount = 0;
    prettyPrintTitle("Test-Suite");
    prettyPrintTitle("Signature-Tests");
    toggleToJWT();
    await signatureTests();
    toggleToJWE();
    prettyPrintTitle("Encryption-Tests");
    await encryptionTests();
    prettyPrintCenter('All tests completed.');
    printTestSummary();
}
// dom.window.onModulesLoaded = () => {
//     console.log("lets go")
// }
// waitForLoad(dom, runTests);
//setTimeout(runTests,10000)
console.log("Mal schauen was wird")

window.runAllTests = runAllTests;
window.encryptionTests = encryptionTests;
window.runEncryptionTests= runEncryptionTests;
window.signatureTests = signatureTests;