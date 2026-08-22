local container = require "container"
local algorithms = require "algorithms"
local util = require "cert.util"
local random = require "ccryptolib.random"
local sha2 = require "sha2"

local crypto = {}

---@alias KeyEncryptor {encrypt: (fun(key: string): RecipientInfo), decrypt: (fun(enc: RecipientInfo): string|nil)}

--- Creates an exchanged key encryptor using an originator certificate and recipient certificate, plus local key.
---@param pk8 PKCS8 The local private key for the originator or receiver
---@param origCert X509 The certificate of the originator
---@param recvCert X509 The certificate of the receiver
---@param algorithm? string The OID of the algorithm to encrypt the key with (defaults to AES256_CBC)
---@return KeyEncryptor encryptor The created key encryptor
function crypto.exchangedKey(pk8, origCert, recvCert, algorithm)
    if algorithm then assert(algorithms.encryption[algorithm], "Unsupported encryption type") end
    local skt = pk8.privateKeyAlgorithm.type.string or pk8.privateKeyAlgorithm.type
    local sct = origCert.toBeSigned.subjectPublicKeyInfo.algorithm.type.string or origCert.toBeSigned.subjectPublicKeyInfo.algorithm.type
    local pct = recvCert.toBeSigned.subjectPublicKeyInfo.algorithm.type.string or recvCert.toBeSigned.subjectPublicKeyInfo.algorithm.type
    assert(algorithms.keyExchange[skt] or skt == container.publicKeyAlgorithmOIDs.ED25519, "Unsupported originator private key type")
    assert(algorithms.keyExchange[sct], "Unsupported originator public key type")
    assert(algorithms.keyExchange[pct], "Unsupported receiver public key type")
    return {
        encrypt = function(key)
            local cryptParam = {type = algorithm or container.encryptionAlgorithmOIDs.AES256_CBC}
            local exchKey = algorithms.keyExchange[sct].exchange(pk8.privateKey, recvCert.toBeSigned.subjectPublicKeyInfo.subjectPublicKey.data)
            ---@type RecipientInfo
            local ri = {
                kari = {
                    version = 3,
                    originator = {
                        issuerAndSerialNumber = {
                            issuer = origCert.toBeSigned.issuer,
                            serialNumber = origCert.toBeSigned.serialNumber
                        }
                    },
                    keyEncryptionAlgorithm = cryptParam,
                    recipientEncryptedKeys = {
                        {
                            encryptedKey = algorithms.encryption[cryptParam.type].encrypt(key, exchKey, cryptParam),
                            rid = {
                                issuerAndSerialNumber = {
                                    issuer = recvCert.toBeSigned.issuer,
                                    serialNumber = recvCert.toBeSigned.serialNumber
                                }
                            }
                        }
                    }
                }
            }
            return ri
        end,
        ---@param enc RecipientInfo
        decrypt = function(enc)
            if not enc.kari or enc.kari.version ~= 3 then return nil end
            if not enc.kari.originator.issuerAndSerialNumber then return nil end
            if not util.compareNames(enc.kari.originator.issuerAndSerialNumber.issuer, origCert.toBeSigned.issuer) then return nil end
            if enc.kari.originator.issuerAndSerialNumber.serialNumber ~= origCert.toBeSigned.serialNumber then return nil end
            local kt = enc.kari.keyEncryptionAlgorithm.type.string or enc.kari.keyEncryptionAlgorithm.type
            if not algorithms.encryption[kt] then return nil end
            for _, v in ipairs(enc.kari.recipientEncryptedKeys) do
                if v.rid.issuerAndSerialNumber and
                    util.compareNames(v.rid.issuerAndSerialNumber.issuer, recvCert.toBeSigned.issuer) and
                    v.rid.issuerAndSerialNumber.serialNumber == recvCert.toBeSigned.serialNumber then
                    local exchKey = algorithms.keyExchange[pct].exchange(pk8.privateKey, origCert.toBeSigned.subjectPublicKeyInfo.subjectPublicKey.data)
                    local ok, res = pcall(algorithms.encryption[kt].decrypt, v.encryptedKey, exchKey, enc.kari.keyEncryptionAlgorithm)
                    if ok and res then return res end
                end
            end
            return nil
        end
    }
end

--- Creates a key encryptor from a pre-shared key.
---@param psk string The pre-shared key to encrypt with
---@param id string An ID for the key
---@param algorithm? string The OID for the algorithm to encrypt the key with (defaults to an AES picked by key length)
---@return KeyEncryptor encryptor The created key encryptor
function crypto.sharedKey(psk, id, algorithm)
    local pkt = algorithm
    if not pkt then
        if #psk == 16 then pkt = container.encryptionAlgorithmOIDs.AES128_CBC
        elseif #psk == 24 then pkt = container.encryptionAlgorithmOIDs.AES192_CBC
        elseif #psk == 32 then pkt = container.encryptionAlgorithmOIDs.AES256_CBC
        else error("Invalid key length", 2) end
    end
    return {
        encrypt = function(key)
            local param = {type = pkt}
            ---@type RecipientInfo
            local ri = {
                kekri = {
                    version = 4,
                    kekid = {
                        subjectKeyIdentifier = id
                    },
                    keyEncryptionAlgorithm = param,
                    encryptedKey = algorithms.encryption[pkt].encrypt(key, psk, param)
                }
            }
            return ri
        end,
        ---@param enc RecipientInfo
        decrypt = function(enc)
            if not enc.kekri or enc.kekri.version ~= 4 then return nil end
            if enc.kekri.kekid.subjectKeyIdentifier ~= id then return nil end
            local kt = enc.kekri.keyEncryptionAlgorithm.type.string or enc.kekri.keyEncryptionAlgorithm.type
            if kt ~= pkt then return nil end
            local ok, res = pcall(algorithms.encryption[pkt].decrypt, enc.kekri.encryptedKey, psk, enc.kekri.keyEncryptionAlgorithm)
            if ok and res then return res end
            return nil
        end
    }
end

--- Creates a key encryptor from a password.
---@param password string The password to encrypt with
---@param hashAlgorithm? string The OID of the algorithm to use to hash the password (from `container.pseudoRandomFunctionOIDs`, defaults to HMAC_SHA256)
---@param iter? number The number of iterations of PBKDF2 (defaults to 4096)
---@param encryptionAlgorithm? string The OID of the algorithm to use to encrypt the key (defaults to AES256_CBC)
---@return KeyEncryptor encryptor The created key encryptor
function crypto.passwordKey(password, hashAlgorithm, iter, encryptionAlgorithm)
    hashAlgorithm = hashAlgorithm or container.pseudoRandomFunctionOIDs.HMAC_SHA256
    encryptionAlgorithm = encryptionAlgorithm or container.encryptionAlgorithmOIDs.AES256_CBC
    assert(algorithms.pseudoRandomFunctions[hashAlgorithm], "Unsupported pseudorandom function")
    assert(algorithms.encryption[encryptionAlgorithm], "Unsupported encryption algorithm")
    local hasher = algorithms.pseudoRandomFunctions[hashAlgorithm].hasher
    local prf, hl = hashAlgorithm, algorithms.pseudoRandomFunctions[hashAlgorithm].bits / 8
    return {
        encrypt = function(key)
            local param = {type = encryptionAlgorithm}
            ---@type RecipientInfo
            local ri = {
                pwri = {
                    version = 0,
                    keyDerivationAlgorithm = {
                        type = container.keyDerivationAlgorithmOIDs.PBKDF2,
                        pbkdf2Parameters = {
                            iterationCount = iter or 4096,
                            salt = {
                                specified = random.random(16)
                            },
                            keyLength = algorithms.encryption[encryptionAlgorithm].keySize,
                            prf = {type = prf}
                        }
                    },
                    keyEncryptionAlgorithm = param,
                    encryptedKey = ""
                }
            }
            local pk = util.pbkdf2(function(d, k) return {sha2.hmac(hasher, k, string.char(table.unpack(d))):byte(1, -1)} end, hl, password, ri.pwri.keyDerivationAlgorithm.pbkdf2Parameters.salt.specified, iter or 4096, algorithms.encryption[encryptionAlgorithm].keySize)
            ri.pwri.encryptedKey = algorithms.encryption[encryptionAlgorithm].encrypt(key, pk, param)
            return ri
        end,
        ---@param enc RecipientInfo
        decrypt = function(enc)
            if not enc.pwri or enc.pwri.version ~= 0 then return nil end
            if not enc.pwri.keyDerivationAlgorithm or (enc.pwri.keyDerivationAlgorithm.type.string or enc.pwri.keyDerivationAlgorithm.type) ~= container.keyDerivationAlgorithmOIDs.PBKDF2 then return nil end
            if not enc.pwri.keyDerivationAlgorithm.pbkdf2Parameters.prf then return nil end
            local prft = enc.pwri.keyDerivationAlgorithm.pbkdf2Parameters.prf.type.string or enc.pwri.keyDerivationAlgorithm.pbkdf2Parameters.prf.type
            if prft ~= prf then return nil end
            local kt = enc.pwri.keyEncryptionAlgorithm.type.string or enc.pwri.keyEncryptionAlgorithm.type
            local kl = algorithms.encryption[kt].keySize
            local pk = util.pbkdf2(function(d, k) return {sha2.hmac(hasher, k, string.char(table.unpack(d))):byte(1, -1)} end, hl, password, enc.pwri.keyDerivationAlgorithm.pbkdf2Parameters.salt.specified, enc.pwri.keyDerivationAlgorithm.pbkdf2Parameters.iterationCount, kl)
            local ok, res = pcall(algorithms.encryption[kt].decrypt, enc.pwri.encryptedKey, pk, enc.pwri.keyEncryptionAlgorithm)
            if ok and res then return res end
            return nil
        end
    }
end

--- Encrypts a string of data into a PKCS#7 container.
--- This may use either an EnvelopedData or AuthEnvelopedData container depending
--- on the selected algorithm.
---@param data string|PKCS7 The data to encrypt
---@param algorithm? string|KeyEncryptor (Optional) The algorithm to use to encrypt (defaults to ChaCha20_Poly1305)
---@param ... KeyEncryptor The key encryptor(s) to encrypt with
---@return PKCS7 pk7 The generated PKCS#7 container
function crypto.encrypt(data, algorithm, ...)
    local ctype = container.pkcs7ContentTypeOIDs.data
    if type(data) == "table" then
        ctype = data.type.string or data.type
        data = container.savePKCS7(data)
    end
    local keyEncryptors = {...}
    if type(algorithm) == "table" then
        table.insert(keyEncryptors, 1, algorithm)
        algorithm = nil
    end
    algorithm = algorithm or container.encryptionAlgorithmOIDs.ChaCha20_Poly1305
    local pk7, key
    if algorithms.authenticatedEncryption[algorithm] then
        key = random.random(algorithms.authenticatedEncryption[algorithm].keySize)
        local param = {type = algorithm}
        local enc, tag = algorithms.authenticatedEncryption[algorithm].encrypt(data, key, param)
        ---@type PKCS7AuthenticatedEncryptedData
        pk7 = {
            type = container.pkcs7ContentTypeOIDs.authEnvelopedData,
            content = {
                version = 0,
                recipientInfos = {},
                authEncryptedContentInfo = {
                    contentEncryptionAlgorithm = param,
                    contentType = ctype,
                    encryptedContent = enc
                },
                mac = tag
            }
        }
    elseif algorithms.encryption[algorithm] then
        key = random.random(algorithms.encryption[algorithm].keySize)
        local param = {type = algorithm}
        ---@type PKCS7EnvelopedData
        pk7 = {
            type = container.pkcs7ContentTypeOIDs.envelopedData,
            content = {
                version = 0,
                recipientInfos = {},
                encryptedContentInfo = {
                    contentEncryptionAlgorithm = param,
                    contentType = ctype,
                    encryptedContent = algorithms.encryption[algorithm].encrypt(data, key, param)
                }
            }
        }
    else error("Unsupported encryption algorithm", 2) end
    for i, v in ipairs(keyEncryptors) do
        pk7.content.recipientInfos[i] = v.encrypt(key)
        if not pk7.content.recipientInfos[i].pwri then pk7.content.version = 2 end
    end
    return pk7
end

--- Decrypts a PKCS#7 container using the specified key.
---@param pk7 PKCS7 The container to decrypt
---@param ... KeyEncryptor|string The key encryptor(s) to decrypt with, or for an EncryptedData container, a string with the password
---@return string|PKCS7 data The decrypted data
function crypto.decrypt(pk7, ...)
    local ctype = pk7.type.string or pk7.type
    if ctype == container.pkcs7ContentTypeOIDs.authEnvelopedData then
        local key
        for _, enc in ipairs{...} do
            for _, ri in ipairs(pk7.content.recipientInfos) do
                key = enc.decrypt(ri)
                if key then break end
            end
            if key then break end
        end
        if not key then error("Could not find valid key encryptor", 2) end
        local algorithm = pk7.content.authEncryptedContentInfo.contentEncryptionAlgorithm
        local data = algorithms.authenticatedEncryption[algorithm.type.string or algorithm.type].decrypt(pk7.content.authEncryptedContentInfo.encryptedContent, key, pk7.content.mac, algorithm)
        if data == nil then error("Could not authenticate data", 2) end
        if (pk7.content.authEncryptedContentInfo.contentType.string or pk7.content.authEncryptedContentInfo.contentType) == container.pkcs7ContentTypeOIDs.data then return data end
        return container.loadPKCS7(data)
    elseif ctype == container.pkcs7ContentTypeOIDs.envelopedData then
        local key
        for _, enc in ipairs{...} do
            for _, ri in ipairs(pk7.content.recipientInfos) do
                key = enc.decrypt(ri)
                if key then break end
            end
            if key then break end
        end
        if not key then error("Could not find valid key encryptor", 2) end
        local algorithm = pk7.content.encryptedContentInfo.contentEncryptionAlgorithm
        local data = algorithms.encryption[algorithm.type.string or algorithm.type].decrypt(pk7.content.encryptedContentInfo.encryptedContent, key, algorithm)
        if data == nil then error("Failed to decrypt data", 2) end
        if (pk7.content.encryptedContentInfo.contentType.string or pk7.content.encryptedContentInfo.contentType) == container.pkcs7ContentTypeOIDs.data then return data end
        return container.loadPKCS7(data)
    elseif ctype == container.pkcs7ContentTypeOIDs.encryptedData then
        assert((pk7.content.encryptedContentInfo.contentEncryptionAlgorithm.type.string or pk7.content.encryptedContentInfo.contentEncryptionAlgorithm.type) == container.passwordBasedEncryptionSchemeOIDs.PBES2, "Unsupported key derivation algorithm")
        local hashAlgorithm = pk7.content.encryptedContentInfo.contentEncryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.prf.type
        local encryptionAlgorithm = pk7.content.encryptedContentInfo.contentEncryptionAlgorithm.pbes2Parameters.encryptionScheme.type
        hashAlgorithm = hashAlgorithm.string or hashAlgorithm
        encryptionAlgorithm = encryptionAlgorithm.string or encryptionAlgorithm
        assert(algorithms.pseudoRandomFunctions[hashAlgorithm], "Unsupported pseudorandom function")
        assert(algorithms.encryption[encryptionAlgorithm], "Unsupported encryption algorithm")
        local hasher = algorithms.pseudoRandomFunctions[hashAlgorithm].hasher
        local hl = algorithms.pseudoRandomFunctions[hashAlgorithm].bits / 8
        local pk = util.pbkdf2(
            hasher, hl, ...,
            pk7.content.encryptedContentInfo.contentEncryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.salt.specified,
            pk7.content.encryptedContentInfo.contentEncryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.iterationCount,
            algorithms.encryption[encryptionAlgorithm].keySize)
        local data = algorithms.encryption[encryptionAlgorithm].decrypt(pk7.content.encryptedContentInfo.encryptedContent, pk, pk7.content.encryptedContentInfo.contentEncryptionAlgorithm.pbes2Parameters.encryptionScheme)
        if data == nil then error("Failed to decrypt data", 2) end
        if (pk7.content.encryptedContentInfo.contentType.string or pk7.content.encryptedContentInfo.contentType) == container.pkcs7ContentTypeOIDs.data then return data end
        return container.loadPKCS7(data)
    else error("Unsupported CMS container type", 2) end
end

--- Encrypts a PKCS#8 key container with a password.
---@param pk8 PKCS8 The key to encrypt
---@param password string The password to encrypt with
---@param hashAlgorithm? string|fun(data: string): string The OID of the algorithm to use to hash the password (from `container.pseudoRandomFunctionOIDs`, defaults to HMAC_SHA256) - function parameter is deprecated, do not use
---@param iter? number The number of iterations of PBKDF2 (defaults to 4096)
---@param encryptionAlgorithm? string The OID of the algorithm to use to encrypt the key (defaults to AES256_CBC)
---@return EncryptedPrivateKeyInfo pk8e The encrypted PKCS#8 container
function crypto.encryptKey(pk8, password, hashAlgorithm, iter, encryptionAlgorithm)
    if type(hashAlgorithm) == "function" then
        for k, v in pairs(algorithms.pseudoRandomFunctions) do
            if v._hasher == hashAlgorithm then
                hashAlgorithm = k
                break
            end
        end
        if type(hashAlgorithm) == "function" then error("Unknown hashing algorithm - hasher functions are deprecated, use an OID instead", 2) end
    end
    hashAlgorithm = hashAlgorithm or container.pseudoRandomFunctionOIDs.HMAC_SHA256
    encryptionAlgorithm = encryptionAlgorithm or container.encryptionAlgorithmOIDs.AES256_CBC
    assert(algorithms.pseudoRandomFunctions[hashAlgorithm], "Unsupported pseudorandom function")
    assert(algorithms.encryption[encryptionAlgorithm], "Unsupported encryption algorithm")
    local hasher = algorithms.pseudoRandomFunctions[hashAlgorithm].hasher
    local prf, hl = hashAlgorithm, algorithms.pseudoRandomFunctions[hashAlgorithm].bits / 8
    local data = container.savePKCS8(pk8)
    local param = {type = encryptionAlgorithm}
    ---@type EncryptedPrivateKeyInfo
    local pk8e = {
        encryptionAlgorithm = {
            type = container.passwordBasedEncryptionSchemeOIDs.PBES2,
            pbes2Parameters = {
                encryptionScheme = param,
                keyDerivationFunc = {
                    type = container.keyDerivationAlgorithmOIDs.PBKDF2,
                    pbkdf2Parameters = {
                        salt = {
                            specified = random.random(16)
                        },
                        iterationCount = iter or 4096,
                        prf = {type = prf}
                    }
                }
            }
        },
        encryptedData = ""
    }
    local key = util.pbkdf2(function(d, k) return {sha2.hmac(hasher, k, string.char(table.unpack(d))):byte(1, -1)} end, hl, password, pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.salt.specified, iter or 4096, algorithms.encryption[encryptionAlgorithm].keySize)
    pk8e.encryptedData = algorithms.encryption[encryptionAlgorithm].encrypt(data, key, param)
    return pk8e
end

--- Decrypts an encrypted PKCS#8 private key.
---@param pk8e EncryptedPrivateKeyInfo The key to decrypt
---@param password string The password to decrypt with
---@return PKCS8 pk8 The decrypted key
function crypto.decryptKey(pk8e, password)
    local ht = pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.prf.type
    local et = pk8e.encryptionAlgorithm.pbes2Parameters.encryptionScheme.type
    if type(ht) == "table" then ht = ht.string end
    if type(et) == "table" then et = et.string end
    assert(algorithms.pseudoRandomFunctions[ht], "Unsupported pseudorandom function")
    assert(algorithms.encryption[et], "Unsupported encryption algorithm")
    local hasher = algorithms.pseudoRandomFunctions[ht].hasher
    local hl = algorithms.pseudoRandomFunctions[ht].bits / 8
    local kl = algorithms.encryption[et].keySize
    local key = util.pbkdf2(function(d, k) return {sha2.hmac(hasher, k, string.char(table.unpack(d))):byte(1, -1)} end, hl, password, pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.salt.specified, pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.iterationCount, kl)
    return container.loadPKCS8(assert(algorithms.encryption[et].decrypt(pk8e.encryptedData, key, pk8e.encryptionAlgorithm.pbes2Parameters.encryptionScheme), "Failed to decrypt"))
end

return crypto
