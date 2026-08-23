local container = require "cert.container"
local util = require "cert.util"
local chacha20 = require "ccryptolib.chacha20"
local ed25519 = require "ccryptolib.ed25519"
local poly1305 = require "ccryptolib.poly1305"
local random = require "ccryptolib.random"
local x25519 = require "ccryptolib.x25519"
local aes = require "aes"
local sha2 = require "sha2"

local algorithms = {
    encryption = {},              ---@type {[string]: {encrypt: (fun(plaintext: string, key: string, params: table): string), decrypt: (fun(enctext: string, key: string, params: table): string|nil), keySize: number}}
    authenticatedEncryption = {}, ---@type {[string]: {encrypt: (fun(plaintext: string, key: string, params: table): string, string), decrypt: (fun(enctext: string, key: string, tag: string, params: table): string|nil), keySize: number}}
    publicKeyEncryption = {},     ---@type {[string]: {encrypt: (fun(plaintext: string, publicKey: string, params: table): string), decrypt: (fun(enctext: string, privateKey: string, params: table): string|nil)}}
    keyExchange = {},             ---@type {[string]: {exchange: (fun(myPrivateKey: string, otherPublicKey: string): string)}}
    signing = {},                 ---@type {[string]: {sign: (fun(data: string, privateKey: string): string), verify: (fun(data: string, publicKey: string, signature: string): boolean)}}
    hashing = {},                 ---@type {[string]: {hash: (fun(data: string): string), bits: number}}
    pseudoRandomFunctions = {},   ---@type {[string]: {hasher: (fun(data: number[], password: string): number[]), bits: number}}
}

local function AESEncryptor(len) return {
    encrypt = function (plaintext, key, params)
        local iv = random.random(16)
        params.iv = iv
        return aes.TableToString(aes.EncryptCBC(util.pkcs7pad(aes.StringToTable(plaintext), len), aes.StringToTable(key), aes.StringToTable(iv)))
    end,
    decrypt = function (enctext, key, params)
        local plaintext = aes.DecryptCBC(aes.StringToTable(enctext), aes.StringToTable(key), aes.StringToTable(params.iv))
        if not plaintext or plaintext[#plaintext] < 1 or plaintext[#plaintext] > 16 then return nil end
        return aes.TableToString(util.pkcs7unpad(plaintext))
    end,
    keySize = len
} end

algorithms.encryption[container.encryptionAlgorithmOIDs.AES128_CBC] = AESEncryptor(16)
algorithms.encryption[container.encryptionAlgorithmOIDs.AES192_CBC] = AESEncryptor(24)
algorithms.encryption[container.encryptionAlgorithmOIDs.AES256_CBC] = AESEncryptor(32)

algorithms.authenticatedEncryption[container.encryptionAlgorithmOIDs.ChaCha20_Poly1305] = {
    encrypt = function (plaintext, key, params)
        local nonce = random.random(12)
        params.nonce = nonce
        return chacha20.crypt(key, nonce, plaintext), poly1305.mac(key, plaintext)
    end,
    decrypt = function (enctext, key, tag, params)
        local plaintext = chacha20.crypt(key, params.nonce, enctext)
        if poly1305.mac(key, plaintext) ~= tag then return nil end
        return plaintext
    end,
    keySize = 32
}

--algorithms.publicKeyEncryption[container.publicKeyAlgorithmOIDs.RSA] = {}

algorithms.keyExchange[container.publicKeyAlgorithmOIDs.X25519] = {exchange = x25519.exchange}

algorithms.signing[container.publicKeyAlgorithmOIDs.ED25519] = {
    sign = function (data, privateKey)
        return ed25519.sign(privateKey, ed25519.publicKey(privateKey), data)
    end,
    verify = function (data, publicKey, signature)
        return ed25519.verify(publicKey, data, signature)
    end
}

algorithms.hashing[container.digestAlgorithmOIDs.SHA1] = {hash = sha2.sha1, bits = 160}
algorithms.hashing[container.digestAlgorithmOIDs.SHA224] = {hash = sha2.sha224, bits = 224}
algorithms.hashing[container.digestAlgorithmOIDs.SHA256] = {hash = sha2.sha256, bits = 256}
algorithms.hashing[container.digestAlgorithmOIDs.SHA384] = {hash = sha2.sha384, bits = 384}
algorithms.hashing[container.digestAlgorithmOIDs.SHA512] = {hash = sha2.sha512, bits = 512}
algorithms.hashing[container.digestAlgorithmOIDs.SHA3_224] = {hash = sha2.sha3_224, bits = 224}
algorithms.hashing[container.digestAlgorithmOIDs.SHA3_256] = {hash = sha2.sha3_256, bits = 256}
algorithms.hashing[container.digestAlgorithmOIDs.SHA3_384] = {hash = sha2.sha3_384, bits = 384}
algorithms.hashing[container.digestAlgorithmOIDs.SHA3_512] = {hash = sha2.sha3_512, bits = 512}

algorithms.pseudoRandomFunctions[container.pseudoRandomFunctionOIDs.HMAC_SHA1] =   {hasher = function(d, k) return {sha2.hmac(sha2.sha1,   k, string.char(table.unpack(d))):gsub("%x%x", function(c) return string.char(tonumber(c, 16)) end):byte(1, -1)} end, bits = 160, _hasher = sha2.sha1  }
algorithms.pseudoRandomFunctions[container.pseudoRandomFunctionOIDs.HMAC_SHA224] = {hasher = function(d, k) return {sha2.hmac(sha2.sha224, k, string.char(table.unpack(d))):gsub("%x%x", function(c) return string.char(tonumber(c, 16)) end):byte(1, -1)} end, bits = 224, _hasher = sha2.sha224}
algorithms.pseudoRandomFunctions[container.pseudoRandomFunctionOIDs.HMAC_SHA256] = {hasher = function(d, k) return {sha2.hmac(sha2.sha256, k, string.char(table.unpack(d))):gsub("%x%x", function(c) return string.char(tonumber(c, 16)) end):byte(1, -1)} end, bits = 256, _hasher = sha2.sha256}
algorithms.pseudoRandomFunctions[container.pseudoRandomFunctionOIDs.HMAC_SHA384] = {hasher = function(d, k) return {sha2.hmac(sha2.sha384, k, string.char(table.unpack(d))):gsub("%x%x", function(c) return string.char(tonumber(c, 16)) end):byte(1, -1)} end, bits = 384, _hasher = sha2.sha384}
algorithms.pseudoRandomFunctions[container.pseudoRandomFunctionOIDs.HMAC_SHA512] = {hasher = function(d, k) return {sha2.hmac(sha2.sha512, k, string.char(table.unpack(d))):gsub("%x%x", function(c) return string.char(tonumber(c, 16)) end):byte(1, -1)} end, bits = 512, _hasher = sha2.sha512}

return algorithms
