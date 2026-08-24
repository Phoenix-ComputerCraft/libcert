#!/bin/bash
set -x

# clone repo + dependencies
git clone https://github.com/Phoenix-ComputerCraft/libcert;
git clone https://github.com/migeyel/ccryptolib;
git clone https://github.com/Phoenix-ComputerCraft/sha2; # use Phoenix's trimmed copy
curl -LO https://gist.githubusercontent.com/afonya2/489c3306a7d85f8f9512df321d904dbb/raw/AES.lua;
git clone https://github.com/Phoenix-ComputerCraft/lua-asn1;

# pack files
function packFile() {
    filename="$1";
    moduleName="$2";
    # output preload header
    echo "package.preload['$moduleName'] = function()";
    # replace system.expect with cc.expect
    sed 's/system.expect/cc.expect/g' "$filename";
    # output preload footer
    echo "end";
    echo "";
}

# system polyfills
cat <<EOF > cert.lua
package.preload['system.filesystem'] = function() return setmetatable({isFile = function(p) return not fs.isDir(p) end}, {__index = fs}) end
package.preload['system.serialization'] = function()
local serialization = {}

--- !doctype module
--- Base64 encoder/decoder
--- @class system.serialization.base64
serialization.base64 = {}

local b64str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

--- Encodes a binary string into Base64.
--- @param str string The string to encode
--- @return string result The string's representation in Base64
function serialization.base64.encode(str)
    expect(1, str, "string")
    local retval = ""
    for s in str:gmatch "..." do
        local n = s:byte(1) * 65536 + s:byte(2) * 256 + s:byte(3)
        local a, b, c, d = bit32.extract(n, 18, 6), bit32.extract(n, 12, 6), bit32.extract(n, 6, 6), bit32.extract(n, 0, 6)
        retval = retval .. b64str:sub(a+1, a+1) .. b64str:sub(b+1, b+1) .. b64str:sub(c+1, c+1) .. b64str:sub(d+1, d+1)
    end
    if #str % 3 == 1 then
        local n = str:byte(-1)
        local a, b = bit32.rshift(n, 2), bit32.lshift(bit32.band(n, 3), 4)
        retval = retval .. b64str:sub(a+1, a+1) .. b64str:sub(b+1, b+1) .. "=="
    elseif #str % 3 == 2 then
        local n = str:byte(-2) * 256 + str:byte(-1)
        local a, b, c = bit32.extract(n, 10, 6), bit32.extract(n, 4, 6), bit32.lshift(bit32.extract(n, 0, 4), 2)
        retval = retval .. b64str:sub(a+1, a+1) .. b64str:sub(b+1, b+1) .. b64str:sub(c+1, c+1) .. "="
    end
    return retval
end

--- Decodes a Base64 string to binary.
--- @param str string The Base64 to decode
--- @return string result The decoded data
function serialization.base64.decode(str)
    expect(1, str, "string")
    local retval = ""
    for s in str:gmatch "...." do
        if s:sub(3, 4) == '==' then
            retval = retval .. string.char(bit32.bor(bit32.lshift(b64str:find(s:sub(1, 1)) - 1, 2), bit32.rshift(b64str:find(s:sub(2, 2)) - 1, 4)))
        elseif s:sub(4, 4) == '=' then
            local n = (b64str:find(s:sub(1, 1))-1) * 4096 + (b64str:find(s:sub(2, 2))-1) * 64 + (b64str:find(s:sub(3, 3))-1)
            retval = retval .. string.char(bit32.extract(n, 10, 8)) .. string.char(bit32.extract(n, 2, 8))
        else
            local n = (b64str:find(s:sub(1, 1))-1) * 262144 + (b64str:find(s:sub(2, 2))-1) * 4096 + (b64str:find(s:sub(3, 3))-1) * 64 + (b64str:find(s:sub(4, 4))-1)
            retval = retval .. string.char(bit32.extract(n, 16, 8)) .. string.char(bit32.extract(n, 8, 8)) .. string.char(bit32.extract(n, 0, 8))
        end
    end
    return retval
end

return serialization
end
EOF
# aes
packFile AES.lua aes >> cert.lua;
# sha2
packFile sha2/usr/lib/sha2.lua sha2 >> cert.lua;
# asn1
packFile lua-asn1/asn1/init.lua asn1 >> cert.lua;
# ccryptolib
mapfile -t ccryptolib_files < <(find ccryptolib/ccryptolib -type f | awk '{ printf "%s ", $1 } { gsub(/^ccryptolib\//, ""); gsub(/\//, "."); gsub(/\.lua$/, ""); print }');
for line in "${ccryptolib_files[@]}"; do
    packFile $line >> cert.lua;
done;
# libcert
mapfile -t libcert_files < <(find libcert/usr/lib/libcert.a -type f | grep -v 'init.lua' | awk '{ printf "%s ", $1 } { gsub(/^libcert\/usr\/lib\/libcert.a/, "cert"); gsub(/\//, "."); gsub(/\.lua$/, ""); print }');
for line in "${libcert_files[@]}"; do
    packFile $line >> cert.lua;
done;
sed 's/system.expect/cc.expect/g' libcert/usr/lib/libcert.a/init.lua >> cert.lua;

# minify
luamin -f cert.lua > cert.min.lua;
exit 0;
