local expect = require "system.expect"
local chain = require "chain"
local container = require "container"
local crypto = require "crypto"
local csr = require "csr"
local signature = require "signature"
local random = require "ccryptolib.random"
local sha2 = require "sha2"

local libcert = {
    chain = chain,
    container = container,
    crypto = crypto,
    csr = csr,
    signature = signature
}

--- Generates an Ed25519 and PKCS#8 private key for signing, optionally encrypted with a password.
---@param password? string A password to encrypt the key with
---@return string key The generated private key
---@return string pk8 The PEM-encoded PKCS#8 key container for the key
function libcert.generatePrivateKeyForSigning(password)
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

--- Generates an X25519 and PKCS#8 private key for encryption, optionally encrypted with a password.
---@param password? string A password to encrypt the key with
---@return string key The generated private key
---@return string pk8 The PEM-encoded PKCS#8 key container for the key
function libcert.generatePrivateKeyForEncryption(password)
    expect(1, password, "string", "nil")
    local key = random.random(32)
    ---@type PKCS8
    local pk8 = {
        version = 1,
        privateKeyAlgorithm = {type = container.publicKeyAlgorithmOIDs.X25519},
        privateKey = key
    }
    if password then
        return key, container.encodePEM(container.savePKCS8Encrypted(crypto.encryptKey(pk8, password)), "ENCRYPTED PRIVATE KEY")
    else return key, container.encodePEM(container.savePKCS8(pk8), "PRIVATE KEY") end
end

local stringNameValues = {
    [container.nameOIDs.uniqueIdentifier] = true,
    [container.nameOIDs.dnQualifier] = true,
    [container.nameOIDs.serialNumber] = true,
    [container.nameOIDs.countryName] = true
}

local dnCodes = {
    C = container.nameOIDs.countryName,
    CN = container.nameOIDs.commonName,
    DC = container.nameOIDs.domainComponent,
    E = container.nameOIDs.emailAddress,
    EMAIL = container.nameOIDs.emailAddress,
    EMAILADDRESS = container.nameOIDs.emailAddress,
    L = container.nameOIDs.localityName,
    O = container.nameOIDs.organizationName,
    OU = container.nameOIDs.organizationalUnitName,
    PC = container.nameOIDs.postalCode,
    S = container.nameOIDs.stateOrProvinceName,
    SN = container.nameOIDs.surname,
    SP = container.nameOIDs.stateOrProvinceName,
    ST = container.nameOIDs.stateOrProvinceName,
    STREET = container.nameOIDs.streetAddress,
    T = container.nameOIDs.title
}

--- Parses an X.500 distinguished name string into a Name.
---@param dn string The distinguished name to parse
---@return Name name The parsed name
local function parseDistinguishedName(dn) -- TODO: export?
    ---@type Name
    local subject = {rdnSequence = {}}
    local partialAttr, partialValue = "", nil
    local escape, partialEscape = false, nil
    for c in dn:gmatch "." do
        if c == '\\' and not escape then
            escape = 1
        elseif c == ',' and not escape then
            if not partialValue then error("Unexpected ','", 2) end
            if partialValue:match "^#" then
                partialValue = partialValue:sub(6):gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end)
            end
            if not stringNameValues[partialAttr] then partialValue = {uTF8String = partialValue} end
            subject.rdnSequence[#subject.rdnSequence+1] = {{type = partialAttr, value = partialValue}}
            partialAttr, partialValue = "", nil
        elseif c == '=' and not escape then
            if partialValue then error("Unexpected '='", 2) end
            if dnCodes[partialAttr] then partialAttr = dnCodes[partialAttr] end
            if not partialAttr:match "^[0-9][0-9%.]*[0-9]$" then error("Invalid OID or attribute", 2) end
            partialValue = ""
        elseif escape == 1 and c:match "%x" then
            partialEscape = tonumber(c, 16)
            escape = 2
        elseif escape == 2 then
            if not c:match "%x" then error("Invalid escape sequence", 2) end
            if partialValue then partialValue = partialValue .. string.char(partialEscape * 16 + tonumber(c, 16))
            else partialAttr = partialAttr .. string.char(partialEscape * 16 + tonumber(c, 16)) end
            escape, partialEscape = false, nil
        else
            if partialValue then partialValue = partialValue .. string.char(partialEscape * 16 + tonumber(c, 16))
            else partialAttr = partialAttr .. string.char(partialEscape * 16 + tonumber(c, 16)) end
            escape = false
        end
    end
    if not partialValue then error("Unexpected end of string", 2) end
    if partialValue:match "^#" then
        partialValue = partialValue:sub(6):gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end)
    end
    if not stringNameValues[partialAttr] then partialValue = {uTF8String = partialValue} end
    subject.rdnSequence[#subject.rdnSequence+1] = {{type = partialAttr, value = partialValue}}
    return subject
end

--- Generates a certificate signing request for a private key.
---@param pk8 string The PEM-encoded PKCS#8 key container to generate for
---@param name {[string]: string}|string The subject of the certificate request, as a key-value map of container.nameOIDs to strings, or as an X.500 distinguished name string
---@param password? string The password protecting the private key, if required
---@return string pk10 The PEM-encoded PKCS#10 CSR container
function libcert.generateCSR(pk8, name, password)
    expect(1, pk8, "string")
    expect(2, name, "table")
    expect(3, password, "string", "nil")
    local der, typ = container.decodePEM(pk8)
    if typ == "ENCRYPTED PRIVATE KEY" then
        if not password then error("Private key is encrypted, but no password was provided", 2) end
        pk8 = crypto.decryptKey(container.loadPKCS8Encrypted(der), password)
    else pk8 = container.loadPKCS8(der) end
    ---@type Name
    local subject = {rdnSequence = {}}
    if type(name) == "string" then
        subject = parseDistinguishedName(name)
    else
        for k, v in pairs(name) do
            if not stringNameValues[k] then v = {uTF8String = v} end
            subject.rdnSequence[#subject.rdnSequence+1] = {
                {
                    type = k,
                    value = v
                }
            }
        end
    end
    return container.encodePEM(container.savePKCS10(csr.generate(pk8, subject)), "CERTIFICATE REQUEST")
end

--- Signs a certificate signature request, creating a new certificate.
---@param pk10 string The PEM-encoded PKCS#10 CSR to sign
---@param cert string The PEM-encoded X.509 certificate of the issuer
---@param pk8 string The PEM-encoded PKCS#8 private key of the issuer
---@param serialNumber number|string The serial number for the new certificate
---@param days number The number of days the certificate is valid for
---@param password? string The password protecting the private key, if required
---@return string outcert The new PEM-encoded X.509 certificate for the request
function libcert.signCSR(pk10, cert, pk8, serialNumber, days, password)
    expect(1, pk10, "string")
    expect(2, cert, "string")
    expect(3, pk8, "string")
    expect(4, serialNumber, "number", "string")
    expect(5, days, "number")
    expect(6, password, "string", "nil")
    local der, typ = container.decodePEM(pk8)
    if typ == "ENCRYPTED PRIVATE KEY" then
        if not password then error("Private key is encrypted, but no password was provided", 2) end
        pk8 = crypto.decryptKey(container.loadPKCS8Encrypted(der), password)
    else pk8 = container.loadPKCS8(der) end
    if type(serialNumber) == "string" then serialNumber = {type = "INTEGER", data = serialNumber} end
    return container.encodePEM(
        container.saveX509(
            csr.sign(
                container.loadPKCS10(container.decodePEM(pk10)),
                container.loadX509(container.decodePEM(cert)),
                pk8,
                serialNumber,
                days
            )
        ), "CERTIFICATE"
    )
end

--- Self-signs a certificate signature request, creating a new certificate.
---@param pk10 string The PEM-encoded PKCS#10 CSR to sign
---@param pk8 string The PEM-encoded PKCS#8 private key of the requester
---@param serialNumber number|string The serial number for the new certificate
---@param days number The number of days the certificate is valid for
---@param password? string The password protecting the private key, if required
---@return string outcert The new PEM-encoded X.509 certificate for the request
function libcert.selfSignCSR(pk10, pk8, serialNumber, days, password)
    expect(1, pk10, "string")
    expect(2, pk8, "string")
    expect(3, serialNumber, "number", "string")
    expect(4, days, "number")
    expect(5, password, "string", "nil")
    local der, typ = container.decodePEM(pk8)
    if typ == "ENCRYPTED PRIVATE KEY" then
        if not password then error("Private key is encrypted, but no password was provided", 2) end
        pk8 = crypto.decryptKey(container.loadPKCS8Encrypted(der), password)
    else pk8 = container.loadPKCS8(der) end
    if type(serialNumber) == "string" then serialNumber = {type = "INTEGER", data = serialNumber} end
    return container.encodePEM(
        container.saveX509(
            csr.selfSign(
                container.loadPKCS10(container.decodePEM(pk10)),
                pk8,
                serialNumber,
                days
            )
        ), "CERTIFICATE"
    )
end

--- Encrypts a block of data with a password.
---@param data string The data to encrypt
---@param password string The password to encrypt with
---@return string pk7 A PEM-encoded PKCS#7/CMS container with the encrypted data
function libcert.encrypt(data, password)
    expect(1, data, "string")
    expect(2, password, "string")
    return container.encodePEM(container.savePKCS7(crypto.encrypt(data, crypto.passwordKey(password))), "CMS")
end

--- Decrypts PEM-encoded PKCS#7 encrypted data with a password.
---@param data string The PEM-encoded PKCS#7 container to decrypt
---@param password string The password to decrypt with
---@return string data The decrypted data
function libcert.decrypt(data, password)
    expect(1, data, "string")
    expect(2, password, "string")
    return crypto.decrypt(container.loadPKCS7(container.decodePEM(data)), crypto.passwordKey(password))
end

--- Encrypts a block of data with a sender's private key + certificate and receiver's certificate.
---@param data string The data to encrypt
---@param myKey string The PEM-encoded PKCS#8 private key of the sender
---@param myCert string The PEM-encoded X.509 certificate of the sender
---@param theirCert string The PEM-encoded X.509 certificate of the receiver
---@param password? string The password protecting the private key, if required
---@return string pk7 A PEM-encoded PKCS#7/CMS container with the encrypted data
function libcert.encryptExchange(data, myKey, myCert, theirCert, password)
    expect(1, data, "string")
    expect(2, myKey, "string")
    expect(3, myCert, "string")
    expect(4, theirCert, "string")
    expect(5, password, "string", "nil")
    local pk8, typ = container.decodePEM(myKey)
    if typ == "ENCRYPTED PRIVATE KEY" then
        if not password then error("Private key is encrypted, but no password was provided", 2) end
        pk8 = crypto.decryptKey(container.loadPKCS8Encrypted(pk8), password)
    else pk8 = container.loadPKCS8(pk8) end
    return container.encodePEM(container.savePKCS7(crypto.encrypt(data, crypto.exchangedKey(pk8, container.loadX509(container.decodePEM(myCert)), container.loadX509(container.decodePEM(theirCert))))), "CMS")
end

--- Decrypts PEM-encoded PKCS#7 encrypted data with a receiver's private key and a sender's certificate.
---@param data string The PEM-encoded PKCS#7 container to decrypt
---@param myKey string The PEM-encoded PKCS#8 private key of the receiver
---@param myCert string The PEM-encoded X.509 certificate of the receiver
---@param theirCert string The PEM-encoded X.509 certificate of the sender
---@param password? string The password protecting the private key, if required
---@return string data The decrypted data
function libcert.decryptExchange(data, myKey, myCert, theirCert, password)
    expect(1, data, "string")
    expect(2, myKey, "string")
    expect(3, myCert, "string")
    expect(4, theirCert, "string")
    expect(5, password, "string", "nil")
    local pk8, typ = container.decodePEM(myKey)
    if typ == "ENCRYPTED PRIVATE KEY" then
        if not password then error("Private key is encrypted, but no password was provided", 2) end
        pk8 = crypto.decryptKey(container.loadPKCS8Encrypted(pk8), password)
    else pk8 = container.loadPKCS8(pk8) end
    return crypto.decrypt(container.loadPKCS7(container.decodePEM(data)), crypto.exchangedKey(pk8, container.loadX509(container.decodePEM(theirCert)), container.loadX509(container.decodePEM(myCert))))
end

--- Creates a PEM-encoded PKCS#7 signature for the specified data, using the keys provided.
---@param cert X509|string The PEM-encoded certificate to sign with
---@param key PKCS8|string The PEM-encoded private key for the certificate
---@param data string The data to sign
---@param additionalCerts? string[] Any additional certificates needed to verify the signature (e.g. CA certificates)
---@param password? string The password for the key, if required
---@param embedData? boolean Whether to embed the signed data in the signature (defaults to false)
---@return string sig The generated signature, PEM-encoded
function libcert.sign(cert, key, data, additionalCerts, password, embedData)
    expect(1, cert, "string", "table")
    expect(2, key, "string", "table")
    expect(3, data, "string")
    expect(4, additionalCerts, "table", "nil")
    expect(5, password, "string", "nil")
    if additionalCerts then
        for i, v in ipairs(additionalCerts) do additionalCerts[i] = container.loadX509(container.decodePEM(v)) end
    end
    if type(cert) == "string" then cert = container.loadX509(container.decodePEM(cert)) end
    if type(key) == "string" then
        local pk8, typ = container.decodePEM(key)
        if typ == "ENCRYPTED PRIVATE KEY" then
            if not password then error("Private key is encrypted, but no password was provided", 2) end
            pk8 = crypto.decryptKey(container.loadPKCS8Encrypted(pk8), password)
        else pk8 = container.loadPKCS8(pk8) end
        key = pk8
    end
    return container.encodePEM(container.savePKCS7(signature.sign(cert, key, data, additionalCerts, embedData)), "PKCS7")
end

--- Verifies the signature of data using a PEM-encoded PKCS#7 signature.
---@param sig string|PKCS7SignedData The PEM-encoded PKCS#7 signature of the original data
---@param data string|nil The data to check (may be `nil` if the data is embedded)
---@param validateCertificate? boolean Whether to validate the certificate's root of trust (defaults to true)
---@param rootPath? string The path to the root certificate store
---@param additionalRoots? (string|X509)[] Any additional root certificates to trust
---@return boolean valid Whether the signature is valid
---@return string|table reason If not valid, a reason why it's invalid; if valid, the data that was verified
function libcert.verify(sig, data, validateCertificate, rootPath, additionalRoots)
    if validateCertificate == nil then validateCertificate = true end
    expect(1, sig, "string", "table")
    expect(2, data, "string", "nil")
    expect(3, validateCertificate, "boolean", "nil")
    expect(4, rootPath, "string", "nil")
    expect(5, additionalRoots, "table", "nil")
    if type(sig) == "string" then sig = container.loadPKCS7(container.decodePEM(sig)) end
    local ok, res = signature.verify(sig, data)
    if not ok then return false, res end
    if validateCertificate then
        if additionalRoots then for i, v in ipairs(additionalRoots) do if type(v) == "string" then additionalRoots[i] = container.loadX509(container.decodePEM(v)) end end end
        local ok, err = chain.validate(signature.getCertificate(sig, 1), sig.content.certificates, rootPath, additionalRoots)
        if not ok then return false, err end
    end
    return true, res
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

local pkcs12PasswordHashParams = {
    [container.digestAlgorithmOIDs.SHA1] = {u = 160, v = 512, H = sha2.sha1},
    [container.digestAlgorithmOIDs.SHA224] = {u = 224, v = 512, H = sha2.sha224},
    [container.digestAlgorithmOIDs.SHA256] = {u = 256, v = 512, H = sha2.sha256},
    [container.digestAlgorithmOIDs.SHA384] = {u = 384, v = 1024, H = sha2.sha384},
    [container.digestAlgorithmOIDs.SHA512] = {u = 512, v = 1024, H = sha2.sha512},
}

---@return string
local function derivePKCS12PasswordKey(password, salt, iterations, hashType)
    password = password:gsub(".", "\0%0") .. "\0\0"
    local hashParams = pkcs12PasswordHashParams[hashType]
    if not hashParams then error("Unsupported digest type", 3) end
    local u, v, H = hashParams.u, hashParams.v, hashParams.H
    local D = ("\3"):rep(v / 8)
    local S = salt:rep(math.ceil(v * math.ceil(#salt * 8 / v) / 8 / #salt)):sub(1, v * math.ceil(#salt * 8 / v) / 8)
    local P = password:rep(math.ceil(v * math.ceil(#password * 8 / v) / 8 / #password)):sub(1, v * math.ceil(#password * 8 / v) / 8)
    local I = S .. P
    local A2 = D .. I
    for _ = 1, iterations do A2 = sha2.hex2bin(H(A2)) end
    return A2
end

--- Unpacks a PKCS#12 bag into a list of individual key/certificate/CRL elements.
--- 
--- This function checks the integrity of the bag based on the value of the
--- integrity parameter and the mode used in the bag:
--- - If the bag has no integrity checking, the parameter is ignored and
---   integrity is not checked.
--- - If the bag has password integrity checking, the parameter may be the
---   password for the bag. If not provided, integrity is not checked.
--- - If the bag has public key integrity checking, the parameter may be
---   either a path to a root certificate store, or a table of root certificates.
---   If not provided, the signature will be checked against the embedded
---   signer certificate without validation; if provided, the chain will be
---   validated to a trusted root.
--- 
--- The encryption parameter currently should be the password for the bag if it
--- is encrypted. Public key encryption is currently not supported.
--- 
---@param pk12 string|PFX The PKCS#12 to unpack
---@param integrity string|X509[]|nil Info for verifying integrity
---@param encryption string|nil The encryption key for the bag, if required
---@return string[] contents A set of PEM-encoded copies of the contents of the bag
function libcert.unpackPKCS12(pk12, integrity, encryption)
    expect(1, pk12, "string", "table")
    if type(pk12) == "string" then
        if pk12:match "^%-%-" then pk12 = container.decodePEM(pk12) end
        pk12 = container.loadPKCS12(pk12)
    end
    if pk12.version > 3 then error("Incompatible PKCS#12 file", 2) end
    if (pk12.authSafe.type.string or pk12.authSafe.type) == container.pkcs7ContentTypeOIDs.data and pk12.macData and integrity then
        expect(2, integrity, "string")
        local key = derivePKCS12PasswordKey(integrity, pk12.macData.macSalt, pk12.macData.iterations, pk12.macData.mac.digestAlgorithm.type.string or pk12.macData.mac.digestAlgorithm.type)
        local mac = sha2.hmac(pkcs12PasswordHashParams[pk12.macData.mac.digestAlgorithm.type.string or pk12.macData.mac.digestAlgorithm.type].H, key, pk12.authSafe.content):gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end)
        if pk12.macData.mac.digest ~= mac then error("PKCS#12 bag failed integrity check (password)", 2) end
    elseif (pk12.authSafe.type.string or pk12.authSafe.type) == container.pkcs7ContentTypeOIDs.signedData then
        expect(2, integrity, "string", "table", "nil")
        local ok, err = libcert.verify(pk12.authSafe, nil, integrity ~= nil, type(integrity) == "string" and integrity or nil, type(integrity) == "table" and integrity or nil)
        if not ok then error("Could not verify PKCS#12 signature: " .. err, 2) end
    end
    local retval = {}
    local function readBags(bags)
        for _, v in ipairs(bags) do
            local contents
            if (v.type.string or v.type) == container.pkcs7ContentTypeOIDs.data then
                contents = container.loadPKCS12SafeContents(v.content)
            elseif (v.type.string or v.type) == container.pkcs7ContentTypeOIDs.encryptedData then
                expect(3, encryption, "string")
                contents = container.loadPKCS12SafeContents(crypto.decrypt(v, encryption))
            elseif (v.type.string or v.type) == container.pkcs7ContentTypeOIDs.envelopedData then
                -- TODO: public key encryption
                error("Public key encryption not supported in PKCS#12", 2)
            end
            if contents then
                for _, bag in ipairs(contents) do
                    if (bag.type.string or bag.type) == container.pkcs12BagTypeOIDs.certBag then
                        if (bag.bagValue.type.string or bag.bagValue.type) ~= container.pkcs12CertTypeOIDs.x509Certificate then error("Unsupported certificate type", 2) end
                        retval[#retval+1] = container.encodePEM(bag.bagValue.certValue, "CERTIFICATE")
                    elseif (bag.type.string or bag.type) == container.pkcs12BagTypeOIDs.keyBag then
                        retval[#retval+1] = container.encodePEM(container.savePKCS8(bag.bagValue), "PRIVATE KEY")
                    elseif (bag.type.string or bag.type) == container.pkcs12BagTypeOIDs.pkcs8ShroudedKeyBag then
                        retval[#retval+1] = container.encodePEM(container.savePKCS8Encrypted(bag.bagValue), "ENCRYPTED PRIVATE KEY")
                    elseif (bag.type.string or bag.type) == container.pkcs12BagTypeOIDs.crlBag then
                        if (bag.bagValue.type.string or bag.bagValue.type) ~= container.pkcs12CrlTypeOIDs.x509Certificate then error("Unsupported certificate type", 2) end
                        retval[#retval+1] = container.encodePEM(bag.bagValue.certValue, "X509 CRL")
                    elseif (bag.type.string or bag.type) == container.pkcs12BagTypeOIDs.secretBag then
                        -- unimplemented
                    elseif (bag.type.string or bag.type) == container.pkcs12BagTypeOIDs.safeContentsBag then
                        readBags(bag.bagValue)
                    end
                end
            end
        end
        return retval
    end
    return readBags(pk12.pdus)
end

--- Returns two values indicating what parameters are required for PKCS#12
--- integrity checking and encryption.
---@param pk12 string|PFX The PKCS#12 to check
---@return "none"|"password"|"publickey" integrity The type of integrity checking used
---@return "none"|"password" encryption The type of encryption used
function libcert.checkPKCS12Parameters(pk12)
    expect(1, pk12, "string", "table")
    if type(pk12) == "string" then
        if pk12:match "^%-%-" then pk12 = container.decodePEM(pk12) end
        pk12 = container.loadPKCS12(pk12)
    end
    if pk12.version > 3 then error("Incompatible PKCS#12 file") end
    local integrity, encryption = "none", "none"
    if pk12.macData then integrity = "password"
    elseif (pk12.authSafe.type.string or pk12.authSafe.type) == container.pkcs7ContentTypeOIDs.signedData then integrity = "publickey" end
    for _, v in ipairs(pk12.pdus) do
        if (v.type.string or v.type) == container.pkcs7ContentTypeOIDs.encryptedData then encryption = "password" break
        elseif (v.type.string or v.type) == container.pkcs7ContentTypeOIDs.envelopedData then encryption = "publickey" break end
    end
    return integrity, encryption
end

--- Prints a PEM-encoded object to the screen for debugging.
---@param data string The PEM object to display
function libcert.print(data)
    local der, typ = container.decodePEM(data)
    local obj
    if typ == "CERTIFICATE" then obj = container.loadX509(der)
    elseif typ == "PKCS#7" or typ == "CMS" then obj = container.loadPKCS7(der)
    elseif typ == "PRIVATE KEY" then obj = container.loadPKCS8(der)
    elseif typ == "ENCRYPTED PRIVATE KEY" then obj = container.loadPKCS8Encrypted(der)
    elseif typ == "CERTIFICATE REQUEST" then obj = container.loadPKCS10(der)
    else error("Unknown PEM data type", 2) end
    return container.print(obj)
end

return libcert
