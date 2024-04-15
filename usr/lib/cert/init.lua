local expect = require "system.expect"
local chain = require "chain"
local container = require "container"
local crypto = require "crypto"
local signature = require "signature"
local util = require "cert.util"
local random = require "ccryptolib.random"

local libcert = {
    chain = chain,
    container = container,
    signature = signature
}

--- Generates an Ed25519 and PKCS#8 private key for encryption and signing, optionally encrypted with a password.
---@param password? string A password to encrypt the key with
---@return string key The generated private key
---@return string pk8 The PEM-encoded PKCS#8 key container for the key
function libcert.generatePrivateKey(password)
    expect(1, password, "string", "nil")
    local key = random.random(32)
    ---@type PKCS8
    local pk8 = {
        version = 1,
        privateKeyAlgorithm = {type = container.signatureAlgorithmOIDs.ED25519},
        privateKey = key
    }
    if password then
        return key, container.encodePEM(container.savePKCS8Encrypted(crypto.encryptKey(pk8, password)), "ENCRYPTED PRIVATE KEY")
    else return key, container.encodePEM(container.savePKCS8(pk8), "PRIVATE KEY") end
end

--- Encrypts a block of data with a password.
---@param data string The data to encrypt
---@param password string The password to encrypt with
---@return string pk7 A PEM-encoded PKCS#7/CMS container with the encrypted data
function libcert.encrypt(data, password)
    expect(1, data, "string")
    expect(1, password, "string")
    return container.encodePEM(container.savePKCS7(crypto.encrypt(data, crypto.passwordKey(password))), "CMS")
end

--- Decrypts PEM-encoded PKCS#7 encrypted data with a password.
---@param data string The PEM-encoded PKCS#7 container to decrypt
---@param password string The password to decrypt with
---@return string data The decrypted data
function libcert.decrypt(data, password)
    expect(1, data, "string")
    expect(1, password, "string")
    return crypto.decrypt(container.loadPKCS7(container.decodePEM(data)), crypto.passwordKey(password))
end

--- Creates a PEM-encoded PKCS#7 signature for the specified data, using the keys provided.
---@param cert X509|string The PEM-encoded certificate to sign with
---@param key PKCS8|string The PEM-encoded private key for the certificate
---@param data string The data to sign
---@param additionalCerts? string[] Any additional certificates needed to verify the signature (e.g. CA certificates)
---@return string sig The generated signature, PEM-encoded
function libcert.sign(cert, key, data, additionalCerts)
    expect(1, cert, "string", "table")
    expect(2, key, "string", "table")
    expect(3, data, "string")
    expect(4, additionalCerts, "table", "nil")
    if additionalCerts then
        for i, v in ipairs(additionalCerts) do additionalCerts[i] = container.loadX509(container.decodePEM(v)) end
    end
    if type(cert) == "string" then cert = container.loadX509(container.decodePEM(cert)) end
    if type(key) == "string" then key = container.loadPKCS8(container.decodePEM(key)) end
    return container.encodePEM(container.savePKCS7(signature.sign(cert, key, data, additionalCerts)), "PKCS7")
end

--- Verifies the signature of data using a PEM-encoded PKCS#7 signature.
---@param sig string|PKCS7SignedData The PEM-encoded PKCS#7 signature of the original data
---@param data string The data to check
---@param validateCertificate? boolean Whether to validate the certificate's root of trust (defaults to true)
---@param rootPath? string The path to the root certificate store
---@param additionalRoots? (string|X509)[] Any additional root certificates to trust
---@return boolean valid Whether the signature is valid
---@return string|nil reason If not valid, a reason why it's invalid
function libcert.verify(sig, data, validateCertificate, rootPath, additionalRoots)
    if validateCertificate == nil then validateCertificate = true end
    expect(1, sig, "string", "table")
    expect(2, data, "string")
    expect(3, validateCertificate, "boolean")
    expect(4, rootPath, "string", "nil")
    expect(5, additionalRoots, "table", "nil")
    if type(sig) == "string" then sig = container.loadPKCS7(container.decodePEM(sig)) end
    local ok, err = signature.verify(sig, data)
    if not ok then return false, err end
    if validateCertificate then
        if additionalRoots then for i, v in ipairs(additionalRoots) do if type(v) == "string" then additionalRoots[i] = container.loadX509(container.decodePEM(v)) end end end
        return chain.validate(signature.getCertificate(sig, 1), sig.content.certificates, rootPath, additionalRoots)
    end
    return true
end

--- Validates a certificate up to a root of trust.
---@param cert string|X509 The certificate to start at
---@param certList? (string|X509)[] Additional certificates that may be in the chain of trust
---@param rootPath? string The path to the root certificate store (defaults to "/etc/certs")
---@param additionalRoots? (string|X509)[] Additional root certificates to trust
---@return boolean trusted Whether the certificate can be trusted
---@return string|nil reason If not trusted, a reason why the certificate failed to validate
function libcert.validate(cert, certList, rootPath, additionalRoots)
    expect(1, cert, "string", "table")
    expect(2, certList, "table", "nil")
    expect(3, rootPath, "string", "nil")
    expect(4, additionalRoots, "string", "nil")
    if type(cert) == "string" then cert = container.loadX509(container.decodePEM(cert)) end
    if certList then for i, v in ipairs(certList) do if type(v) == "string" then certList[i] = container.loadX509(container.decodePEM(v)) end end end
    if additionalRoots then for i, v in ipairs(additionalRoots) do if type(v) == "string" then additionalRoots[i] = container.loadX509(container.decodePEM(v)) end end end
    return chain.validate(cert, certList, rootPath, additionalRoots)
end

return libcert
