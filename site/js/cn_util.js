// Copyright (c) 2014-2015, MyMonero.com
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Original Author: Lucas Jones
// Modified by luigi1111 2016

var cnUtil = (function(initConfig) {
    var config = $.extend({}, initConfig);
    config.coinUnits = new JSBigInt(10).pow(config.coinUnitPlaces);

    var HASH_STATE_BYTES = 200;
    var HASH_SIZE = 32;
    var ADDRESS_CHECKSUM_SIZE = 4;
    var INTEGRATED_ID_SIZE = 8;
    var ENCRYPTED_PAYMENT_ID_TAIL = 141;
    var CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = config.addressPrefix;
    var CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = config.integratedAddressPrefix;
    var UINT64_MAX = new JSBigInt(2).pow(64);
    var CURRENT_TX_VERSION = 1;
    var TX_EXTRA_NONCE_MAX_COUNT = 255;
    var TX_EXTRA_TAGS = {
        PADDING: '00',
        PUBKEY: '01',
        NONCE: '02',
        MERGE_MINING: '03'
    };
    var TX_EXTRA_NONCE_TAGS = {
        PAYMENT_ID: '00',
        ENCRYPTED_PAYMENT_ID: '01'
    };
    var KEY_SIZE = 32;
    var STRUCT_SIZES = {
        GE_P3: 160,
        GE_P2: 120,
        GE_P1P1: 160,
        GE_CACHED: 160,
        EC_SCALAR: 32,
        EC_POINT: 32,
        KEY_IMAGE: 32,
        GE_DSMP: 160 * 8, // ge_cached * 8
        SIGNATURE: 64 // ec_scalar * 2
    };

    //RCT vars
    var H = "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"; //base H for amounts
    var l = JSBigInt("7237005577332262213973186563042994240857116359379907606001950938285454250989"); //curve order (not RCT specific)
    var I = "0100000000000000000000000000000000000000000000000000000000000000"; //identity element
    var Z = "0000000000000000000000000000000000000000000000000000000000000000"; //zero scalar
    //H2 object to speed up some operations
    var H2 = ["8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94", "8faa448ae4b3e2bb3d4d130909f55fcd79711c1c83cdbccadd42cbe1515e8712",
        "12a7d62c7791654a57f3e67694ed50b49a7d9e3fc1e4c7a0bde29d187e9cc71d", "789ab9934b49c4f9e6785c6d57a498b3ead443f04f13df110c5427b4f214c739",
        "771e9299d94f02ac72e38e44de568ac1dcb2edc6edb61f83ca418e1077ce3de8", "73b96db43039819bdaf5680e5c32d741488884d18d93866d4074a849182a8a64",
        "8d458e1c2f68ebebccd2fd5d379f5e58f8134df3e0e88cad3d46701063a8d412", "09551edbe494418e81284455d64b35ee8ac093068a5f161fa6637559177ef404",
        "d05a8866f4df8cee1e268b1d23a4c58c92e760309786cdac0feda1d247a9c9a7", "55cdaad518bd871dd1eb7bc7023e1dc0fdf3339864f88fdd2de269fe9ee1832d",
        "e7697e951a98cfd5712b84bbe5f34ed733e9473fcb68eda66e3788df1958c306", "f92a970bae72782989bfc83adfaa92a4f49c7e95918b3bba3cdc7fe88acc8d47",
        "1f66c2d491d75af915c8db6a6d1cb0cd4f7ddcd5e63d3ba9b83c866c39ef3a2b", "3eec9884b43f58e93ef8deea260004efea2a46344fc5965b1a7dd5d18997efa7",
        "b29f8f0ccb96977fe777d489d6be9e7ebc19c409b5103568f277611d7ea84894", "56b1f51265b9559876d58d249d0c146d69a103636699874d3f90473550fe3f2c",
        "1d7a36575e22f5d139ff9cc510fa138505576b63815a94e4b012bfd457caaada", "d0ac507a864ecd0593fa67be7d23134392d00e4007e2534878d9b242e10d7620",
        "f6c6840b9cf145bb2dccf86e940be0fc098e32e31099d56f7fe087bd5deb5094", "28831a3340070eb1db87c12e05980d5f33e9ef90f83a4817c9f4a0a33227e197",
        "87632273d629ccb7e1ed1a768fa2ebd51760f32e1c0b867a5d368d5271055c6e", "5c7b29424347964d04275517c5ae14b6b5ea2798b573fc94e6e44a5321600cfb",
        "e6945042d78bc2c3bd6ec58c511a9fe859c0ad63fde494f5039e0e8232612bd5", "36d56907e2ec745db6e54f0b2e1b2300abcb422e712da588a40d3f1ebbbe02f6",
        "34db6ee4d0608e5f783650495a3b2f5273c5134e5284e4fdf96627bb16e31e6b", "8e7659fb45a3787d674ae86731faa2538ec0fdf442ab26e9c791fada089467e9",
        "3006cf198b24f31bb4c7e6346000abc701e827cfbb5df52dcfa42e9ca9ff0802", "f5fd403cb6e8be21472e377ffd805a8c6083ea4803b8485389cc3ebc215f002a",
        "3731b260eb3f9482e45f1c3f3b9dcf834b75e6eef8c40f461ea27e8b6ed9473d", "9f9dab09c3f5e42855c2de971b659328a2dbc454845f396ffc053f0bb192f8c3",
        "5e055d25f85fdb98f273e4afe08464c003b70f1ef0677bb5e25706400be620a5", "868bcf3679cb6b500b94418c0b8925f9865530303ae4e4b262591865666a4590",
        "b3db6bd3897afbd1df3f9644ab21c8050e1f0038a52f7ca95ac0c3de7558cb7a", "8119b3a059ff2cac483e69bcd41d6d27149447914288bbeaee3413e6dcc6d1eb",
        "10fc58f35fc7fe7ae875524bb5850003005b7f978c0c65e2a965464b6d00819c", "5acd94eb3c578379c1ea58a343ec4fcff962776fe35521e475a0e06d887b2db9",
        "33daf3a214d6e0d42d2300a7b44b39290db8989b427974cd865db011055a2901", "cfc6572f29afd164a494e64e6f1aeb820c3e7da355144e5124a391d06e9f95ea",
        "d5312a4b0ef615a331f6352c2ed21dac9e7c36398b939aec901c257f6cbc9e8e", "551d67fefc7b5b9f9fdbf6af57c96c8a74d7e45a002078a7b5ba45c6fde93e33",
        "d50ac7bd5ca593c656928f38428017fc7ba502854c43d8414950e96ecb405dc3", "0773e18ea1be44fe1a97e239573cfae3e4e95ef9aa9faabeac1274d3ad261604",
        "e9af0e7ca89330d2b8615d1b4137ca617e21297f2f0ded8e31b7d2ead8714660", "7b124583097f1029a0c74191fe7378c9105acc706695ed1493bb76034226a57b",
        "ec40057b995476650b3db98e9db75738a8cd2f94d863b906150c56aac19caa6b", "01d9ff729efd39d83784c0fe59c4ae81a67034cb53c943fb818b9d8ae7fc33e5",
        "00dfb3c696328c76424519a7befe8e0f6c76f947b52767916d24823f735baf2e", "461b799b4d9ceea8d580dcb76d11150d535e1639d16003c3fb7e9d1fd13083a8",
        "ee03039479e5228fdc551cbde7079d3412ea186a517ccc63e46e9fcce4fe3a6c", "a8cfb543524e7f02b9f045acd543c21c373b4c9b98ac20cec417a6ddb5744e94",
        "932b794bf89c6edaf5d0650c7c4bad9242b25626e37ead5aa75ec8c64e09dd4f", "16b10c779ce5cfef59c7710d2e68441ea6facb68e9b5f7d533ae0bb78e28bf57",
        "0f77c76743e7396f9910139f4937d837ae54e21038ac5c0b3fd6ef171a28a7e4", "d7e574b7b952f293e80dde905eb509373f3f6cd109a02208b3c1e924080a20ca",
        "45666f8c381e3da675563ff8ba23f83bfac30c34abdde6e5c0975ef9fd700cb9", "b24612e454607eb1aba447f816d1a4551ef95fa7247fb7c1f503020a7177f0dd",
        "7e208861856da42c8bb46a7567f8121362d9fb2496f131a4aa9017cf366cdfce", "5b646bff6ad1100165037a055601ea02358c0f41050f9dfe3c95dccbd3087be0",
        "746d1dccfed2f0ff1e13c51e2d50d5324375fbd5bf7ca82a8931828d801d43ab", "cb98110d4a6bb97d22feadbc6c0d8930c5f8fc508b2fc5b35328d26b88db19ae",
        "60b626a033b55f27d7676c4095eababc7a2c7ede2624b472e97f64f96b8cfc0e", "e5b52bc927468df71893eb8197ef820cf76cb0aaf6e8e4fe93ad62d803983104",
        "056541ae5da9961be2b0a5e895e5c5ba153cbb62dd561a427bad0ffd41923199", "f8fef05a3fa5c9f3eba41638b247b711a99f960fe73aa2f90136aeb20329b888"];

    //begin rct new functions
    //creates a Pedersen commitment from an amount (in scalar form) and a mask
    //C = bG + aH where b = mask, a = amount
    function commit(amount, mask){
        if (!valid_hex(mask) || mask.length !== 64 || !valid_hex(amount) || amount.length !== 64){
            throw "invalid amount or mask!";
        }
        var C = ge_double_scalarmult_base_vartime(amount, H, mask);
        return C;
    }

    //switch byte order for hex string
    function swapEndian(hex){
        if (hex.length % 2 !== 0){return "length must be a multiple of 2!";}
        var data = "";
        for (var i=1; i <= hex.length / 2; i++){
            data += hex.substr(0 - 2 * i, 2);
        }
        return data;
    }

    //switch byte order charwise
    function swapEndianC(string){
        var data = "";
        for (var i=1; i <= string.length; i++){
            data += string.substr(0 - i, 1);
        }
        return data;
    }

    //for most uses you'll also want to swapEndian after conversion
    //mainly to convert integer "scalars" to usable hexadecimal strings
    function d2h(integer){
        if (typeof integer !== "string" && integer.toString().length > 15){throw "integer should be entered as a string for precision";}
        var padding = "";
        for (i = 0; i < 63; i++){
            padding += "0";
        }
        return (padding + JSBigInt(integer).toString(16).toLowerCase()).slice(-64);
    }

    //integer to scalar
    function d2s(integer){
        return swapEndian(d2h(integer));
    }

    function s2d(scalar){
        return JSBigInt.parse(swapEndian(scalar), 16).toString();
    }

    //convert integer string to 64bit "binary" little-endian string
    function d2b(integer){
        if (typeof integer !== "string" && integer.toString().length > 15){throw "integer should be entered as a string for precision";}
        var padding = "";
        for (i = 0; i < 63; i++){
            padding += "0";
        }
        var a = new JSBigInt(integer);
        if (a.toString(2).length > 64){throw "amount overflows uint64!";}
        return swapEndianC((padding + a.toString(2)).slice(-64));
    }

    //convert integer string to 64bit base 4 little-endian string
    function d2b4(integer){
        if (typeof integer !== "string" && integer.toString().length > 15){throw "integer should be entered as a string for precision";}
        var padding = "";
        for (i = 0; i < 31; i++){
            padding += "0";
        }
        var a = new JSBigInt(integer);
        if (a.toString(2).length > 64){throw "amount overflows uint64!";}
        return swapEndianC((padding + a.toString(4)).slice(-32));
    }
    //end rct new functions

    this.valid_hex = function(hex) {
        var exp = new RegExp("[0-9a-fA-F]{" + hex.length + "}");
        return exp.test(hex);
    };

    //simple exclusive or function for two hex inputs
    this.hex_xor = function(hex1, hex2) {
        if (!hex1 || !hex2 || hex1.length !== hex2.length || hex1.length % 2 !== 0 || hex2.length % 2 !== 0){throw "Hex string(s) is/are invalid!";}
        var bin1 = hextobin(hex1);
        var bin2 = hextobin(hex2);
        var xor = new Uint8Array(bin1.length);
        for (i = 0; i < xor.length; i++){
            xor[i] = bin1[i] ^ bin2[i];
        }
        return bintohex(xor);
    };

    function hextobin(hex) {
        if (hex.length % 2 !== 0) throw "Hex string has invalid length!";
        var res = new Uint8Array(hex.length / 2);
        for (var i = 0; i < hex.length / 2; ++i) {
            res[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }
        return res;
    }

    function bintohex(bin) {
        var out = [];
        for (var i = 0; i < bin.length; ++i) {
            out.push(("0" + bin[i].toString(16)).slice(-2));
        }
        return out.join("");
    }

    // Generate a 256-bit crypto random
    this.rand_32 = function() {
        return mn_random(256);
    };

    // Generate a 128-bit crypto random
    this.rand_16 = function() {
        return mn_random(128);
    };

    this.encode_varint = function(i) {
        i = new JSBigInt(i);
        var out = '';
        // While i >= b10000000
        while (i.compare(0x80) >= 0) {
            // out.append i & b01111111 | b10000000
            out += ("0" + ((i.lowVal() & 0x7f) | 0x80).toString(16)).slice(-2);
            i = i.divide(new JSBigInt(2).pow(7));
        }
        out += ("0" + i.toJSValue().toString(16)).slice(-2);
        return out;
    };

    this.sc_reduce = function(hex) {
        var input = hextobin(hex);
        if (input.length !== 64) {
            throw "Invalid input length";
        }
        var mem = Module._malloc(64);
        Module.HEAPU8.set(input, mem);
        Module.ccall('sc_reduce', 'void', ['number'], [mem]);
        var output = Module.HEAPU8.subarray(mem, mem + 64);
        Module._free(mem);
        return bintohex(output);
    };

    this.sc_reduce32 = function(hex) {
        var input = hextobin(hex);
        if (input.length !== 32) {
            throw "Invalid input length";
        }
        var mem = Module._malloc(32);
        Module.HEAPU8.set(input, mem);
        Module.ccall('sc_reduce32', 'void', ['number'], [mem]);
        var output = Module.HEAPU8.subarray(mem, mem + 32);
        Module._free(mem);
        return bintohex(output);
    };

    this.cn_fast_hash = function(input, inlen) {
        /*if (inlen === undefined || !inlen) {
            inlen = Math.floor(input.length / 2);
        }*/
        if (input.length % 2 !== 0 || !this.valid_hex(input)) {
            throw "Input invalid";
        }
        //update to use new keccak impl (approx 45x faster)
        //var state = this.keccak(input, inlen, HASH_STATE_BYTES);
        //return state.substr(0, HASH_SIZE * 2);
        return keccak_256(hextobin(input));
    };

    this.sec_key_to_pub = function(sec) {
        var input = hextobin(sec);
        if (input.length !== 32) {
            throw "Invalid input length";
        }
        var input_mem = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(input, input_mem);
        var ge_p3 = Module._malloc(STRUCT_SIZES.GE_P3);
        var out_mem = Module._malloc(KEY_SIZE);
        Module.ccall('ge_scalarmult_base', 'void', ['number', 'number'], [ge_p3, input_mem]);
        Module.ccall('ge_p3_tobytes', 'void', ['number', 'number'], [out_mem, ge_p3]);
        var output = Module.HEAPU8.subarray(out_mem, out_mem + KEY_SIZE);
        Module._free(ge_p3);
        Module._free(input_mem);
        Module._free(out_mem);
        return bintohex(output);
    };

    //"alias" for naming compatibility -- we really can have our cake and eat it too
    this.ge_scalarmult_base = function(sec) {
        return this.sec_key_to_pub(sec);
    };

    //accepts arbitrary point, rather than G
    this.ge_scalarmult = function(pub, sec) {
        if (pub.length !== 64 || sec.length !== 64) {
            throw "Invalid input length";
        }
        var pub_b = hextobin(pub);
        var sec_b = hextobin(sec);
        var pub_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(pub_b, pub_m);
        var sec_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(sec_b, sec_m);
        var ge_p3_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var ge_p2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        if (Module.ccall("ge_frombytes_vartime", "bool", ["number", "number"], [ge_p3_m, pub_m]) !== 0) {
            throw "ge_frombytes_vartime returned non-zero error code";
        }
        Module.ccall("ge_scalarmult", "void", ["number", "number", "number"], [ge_p2_m, sec_m, ge_p3_m]);
        var derivation_m = Module._malloc(KEY_SIZE);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [derivation_m, ge_p2_m]);
        var res = Module.HEAPU8.subarray(derivation_m, derivation_m + KEY_SIZE);
        Module._free(pub_m);
        Module._free(sec_m);
        Module._free(ge_p3_m);
        Module._free(ge_p2_m);
        Module._free(derivation_m);
        return bintohex(res);
    };

    this.pubkeys_to_string = function(spend, view) {
        var prefix = this.encode_varint(CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
        var data = prefix + spend + view;
        var checksum = this.cn_fast_hash(data);
        return cnBase58.encode(data + checksum.slice(0, ADDRESS_CHECKSUM_SIZE * 2));
    };

    // Generate keypair from seed
    this.generate_keys = function(seed) {
        if (seed.length !== 64) throw "Invalid input length!";
        var sec = this.sc_reduce32(seed);
        //var point = this.ge_scalarmult_base(sec);
        //var pub = this.ge_p3_tobytes(point);
        var pub = this.sec_key_to_pub(sec);
        return {
            'sec': sec,
            'pub': pub
        };
    };

    this.random_keypair = function() {
        return this.generate_keys(this.rand_32());
    };

    // Random 32-byte ec scalar
    this.random_scalar = function() {
        //var rand = this.sc_reduce(mn_random(64 * 8));
        //return rand.slice(0, STRUCT_SIZES.EC_SCALAR * 2);
        return this.sc_reduce32(this.rand_32());
    };

    /* no longer used - this.keccak = function(hex, inlen, outlen) {
        var input = hextobin(hex);
        if (input.length !== inlen) {
            throw "Invalid input length";
        }
        if (outlen <= 0) {
            throw "Invalid output length";
        }
        var input_mem = Module._malloc(inlen);
        Module.HEAPU8.set(input, input_mem);
        var out_mem = Module._malloc(outlen);
        Module._keccak(input_mem, inlen | 0, out_mem, outlen | 0);
        var output = Module.HEAPU8.subarray(out_mem, out_mem + outlen);
        Module._free(input_mem);
        Module._free(out_mem);
        return bintohex(output);
    };*/

    this.create_address = function(seed) {
        var keys = {};
        var first;
        if (seed.length !== 64) {
            first = this.cn_fast_hash(seed);
        } else {
            first = seed; //only input reduced seeds or this will not give you the result you want
        }
        keys.spend = this.generate_keys(first);
        var second = this.cn_fast_hash(first);
        keys.view = this.generate_keys(second);
        keys.public_addr = this.pubkeys_to_string(keys.spend.pub, keys.view.pub);
        return keys;
    };

    this.create_addr_prefix = function(seed) {
        var first;
        if (seed.length !== 64) {
            first = this.cn_fast_hash(seed);
        } else {
            first = seed;
        }
        var spend = this.generate_keys(first);
        var prefix = this.encode_varint(CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
        return cnBase58.encode(prefix + spend.pub).slice(0, 44);
    };
    
    this.decode_address = function(address) {
        var dec = cnBase58.decode(address);
        var expectedPrefix = this.encode_varint(CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
        var expectedPrefixInt = this.encode_varint(CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX);
        var prefix = dec.slice(0, expectedPrefix.length);
        if (prefix !== expectedPrefix && prefix !== expectedPrefixInt) {
            throw "Invalid address prefix";
        }
        dec = dec.slice(expectedPrefix.length);
        var spend = dec.slice(0, 64);
        var view = dec.slice(64, 128);
        if (prefix === expectedPrefixInt){
            var intPaymentId = dec.slice(128, 128 + (INTEGRATED_ID_SIZE * 2));
            var checksum = dec.slice(128 + (INTEGRATED_ID_SIZE * 2), 128 + (INTEGRATED_ID_SIZE * 2) + (ADDRESS_CHECKSUM_SIZE * 2));
            var expectedChecksum = this.cn_fast_hash(prefix + spend + view + intPaymentId).slice(0, ADDRESS_CHECKSUM_SIZE * 2);
        } else {
            var checksum = dec.slice(128, 128 + (ADDRESS_CHECKSUM_SIZE * 2));
            var expectedChecksum = this.cn_fast_hash(prefix + spend + view).slice(0, ADDRESS_CHECKSUM_SIZE * 2);
        }
        if (checksum !== expectedChecksum) {
            throw "Invalid checksum";
        }
        if (intPaymentId){
            return {
                spend: spend,
                view: view,
                intPaymentId: intPaymentId
            };
        } else {
            return {
                spend: spend,
                view: view
            };
        }
    };

    this.valid_keys = function(view_pub, view_sec, spend_pub, spend_sec) {
        var expected_view_pub = this.sec_key_to_pub(view_sec);
        var expected_spend_pub = this.sec_key_to_pub(spend_sec);
        return (expected_spend_pub === spend_pub) && (expected_view_pub === view_pub);
    };

    this.decode_rct_ecdh = function(ecdh, key) {
        var first = this.hash_to_scalar(key);
        var second = this.hash_to_scalar(first);
        return {
            "mask": sc_sub(ecdh.mask, first),
            "amount": sc_sub(ecdh.amount, second)
        };
    };

    this.encode_rct_ecdh = function(ecdh, key) {
        var first = this.hash_to_scalar(key);
        var second = this.hash_to_scalar(first);
        return {
            "mask": sc_add(ecdh.mask, first),
            "amount": sc_add(ecdh.amount)
        };
    };

    this.hash_to_scalar = function(buf) {
        var hash = this.cn_fast_hash(buf);
        var scalar = this.sc_reduce32(hash);
        return scalar;
    };

    this.generate_key_derivation = function(pub, sec) {
        if (pub.length !== 64 || sec.length !== 64) {
            throw "Invalid input length";
        }
        var pub_b = hextobin(pub);
        var sec_b = hextobin(sec);
        var pub_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(pub_b, pub_m);
        var sec_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(sec_b, sec_m);
        var ge_p3_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var ge_p2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var ge_p1p1_m = Module._malloc(STRUCT_SIZES.GE_P1P1);
        if (Module.ccall("ge_frombytes_vartime", "bool", ["number", "number"], [ge_p3_m, pub_m]) !== 0) {
            throw "ge_frombytes_vartime returned non-zero error code";
        }
        Module.ccall("ge_scalarmult", "void", ["number", "number", "number"], [ge_p2_m, sec_m, ge_p3_m]);
        Module.ccall("ge_mul8", "void", ["number", "number"], [ge_p1p1_m, ge_p2_m]);
        Module.ccall("ge_p1p1_to_p2", "void", ["number", "number"], [ge_p2_m, ge_p1p1_m]);
        var derivation_m = Module._malloc(KEY_SIZE);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [derivation_m, ge_p2_m]);
        var res = Module.HEAPU8.subarray(derivation_m, derivation_m + KEY_SIZE);
        Module._free(pub_m);
        Module._free(sec_m);
        Module._free(ge_p3_m);
        Module._free(ge_p2_m);
        Module._free(ge_p1p1_m);
        Module._free(derivation_m);
        return bintohex(res);
    };

    //"alias" for backwards compatibility
    this.generate_key_derivation_2 = function(pub, sec) {
        return this.ge_scalarmult(pub, sec);
    };

    this.derivation_to_scalar = function(derivation, output_index) {
        var buf = "";
        if (derivation.length !== (STRUCT_SIZES.EC_POINT * 2)) {
            throw "Invalid derivation length!";
        }
        buf += derivation;
        var enc = encode_varint(output_index);
        if (enc.length > 10 * 2) {
            throw "output_index didn't fit in 64-bit varint";
        }
        buf += enc;
        return this.hash_to_scalar(buf);
    };

    this.derive_secret_key = function(derivation, out_index, sec) {
        if (derivation.length !== 64 || sec.length !== 64) {
            throw "Invalid input length!";
        }
        var scalar_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var scalar_b = hextobin(this.derivation_to_scalar(derivation, out_index));
        Module.HEAPU8.set(scalar_b, scalar_m);
        var base_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(sec), base_m);
        var derived_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        Module.ccall("sc_add", "void", ["number", "number", "number"], [derived_m, base_m, scalar_m]);
        var res = Module.HEAPU8.subarray(derived_m, derived_m + STRUCT_SIZES.EC_SCALAR);
        Module._free(scalar_m);
        Module._free(base_m);
        Module._free(derived_m);
        return bintohex(res);
    };

    this.derive_public_key = function(derivation, out_index, pub) {
        if (derivation.length !== 64 || pub.length !== 64) {
            throw "Invalid input length!";
        }
        var derivation_m = Module._malloc(KEY_SIZE);
        var derivation_b = hextobin(derivation);
        Module.HEAPU8.set(derivation_b, derivation_m);
        var base_m = Module._malloc(KEY_SIZE);
        var base_b = hextobin(pub);
        Module.HEAPU8.set(base_b, base_m);
        var point1_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var point2_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var point3_m = Module._malloc(STRUCT_SIZES.GE_CACHED);
        var point4_m = Module._malloc(STRUCT_SIZES.GE_P1P1);
        var point5_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var derived_key_m = Module._malloc(KEY_SIZE);
        if (Module.ccall("ge_frombytes_vartime", "bool", ["number", "number"], [point1_m, base_m]) !== 0) {
            throw "ge_frombytes_vartime returned non-zero error code";
        }
        var scalar_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var scalar_b = hextobin(this.derivation_to_scalar(bintohex(Module.HEAPU8.subarray(derivation_m, derivation_m + STRUCT_SIZES.EC_POINT)), out_index));
        Module.HEAPU8.set(scalar_b, scalar_m);
        Module.ccall("ge_scalarmult_base", "void", ["number", "number"], [point2_m, scalar_m]);
        Module.ccall("ge_p3_to_cached", "void", ["number", "number"], [point3_m, point2_m]);
        Module.ccall("ge_add", "void", ["number", "number", "number"], [point4_m, point1_m, point3_m]);
        Module.ccall("ge_p1p1_to_p2", "void", ["number", "number"], [point5_m, point4_m]);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [derived_key_m, point5_m]);
        var res = Module.HEAPU8.subarray(derived_key_m, derived_key_m + KEY_SIZE);
        Module._free(derivation_m);
        Module._free(base_m);
        Module._free(scalar_m);
        Module._free(point1_m);
        Module._free(point2_m);
        Module._free(point3_m);
        Module._free(point4_m);
        Module._free(point5_m);
        Module._free(derived_key_m);
        return bintohex(res);
    };

    this.hash_to_ec = function(key) {
        if (key.length !== (KEY_SIZE * 2)) {
            throw "Invalid input length";
        }
        var h_m = Module._malloc(HASH_SIZE);
        var point_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var point2_m = Module._malloc(STRUCT_SIZES.GE_P1P1);
        var res_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var hash = hextobin(this.cn_fast_hash(key, KEY_SIZE));
        Module.HEAPU8.set(hash, h_m);
        Module.ccall("ge_fromfe_frombytes_vartime", "void", ["number", "number"], [point_m, h_m]);
        Module.ccall("ge_mul8", "void", ["number", "number"], [point2_m, point_m]);
        Module.ccall("ge_p1p1_to_p3", "void", ["number", "number"], [res_m, point2_m]);
        var res = Module.HEAPU8.subarray(res_m, res_m + STRUCT_SIZES.GE_P3);
        Module._free(h_m);
        Module._free(point_m);
        Module._free(point2_m);
        Module._free(res_m);
        return bintohex(res);
    };

    //returns a 32 byte point via "ge_p3_tobytes" rather than a 160 byte "p3", otherwise same as above;
    hash_to_ec_2 = function(key) {
        if (key.length !== (KEY_SIZE * 2)) {
            throw "Invalid input length";
        }
        var h_m = Module._malloc(HASH_SIZE);
        var point_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var point2_m = Module._malloc(STRUCT_SIZES.GE_P1P1);
        var res_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var hash = hextobin(this.cn_fast_hash(key, KEY_SIZE));
        var res2_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hash, h_m);
        Module.ccall("ge_fromfe_frombytes_vartime", "void", ["number", "number"], [point_m, h_m]);
        Module.ccall("ge_mul8", "void", ["number", "number"], [point2_m, point_m]);
        Module.ccall("ge_p1p1_to_p3", "void", ["number", "number"], [res_m, point2_m]);
        Module.ccall("ge_p3_tobytes", "void", ["number", "number"], [res2_m, res_m]);
        var res = Module.HEAPU8.subarray(res2_m, res2_m + KEY_SIZE);
        Module._free(h_m);
        Module._free(point_m);
        Module._free(point2_m);
        Module._free(res_m);
        Module._free(res2_m);
        return bintohex(res);
    };

    //does not ensure point is in group of G, also returns 32 bytes
    hash_to_ec_3 = function(key) {
        if (key.length !== (KEY_SIZE * 2)) {
            throw "Invalid input length";
        }
        var h_m = Module._malloc(HASH_SIZE);
        var point_m = Module._malloc(STRUCT_SIZES.GE_P2);
        //var point2_m = Module._malloc(STRUCT_SIZES.GE_P1P1);
        //var res_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var hash = hextobin(this.cn_fast_hash(key, KEY_SIZE));
        var res2_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hash, h_m);
        Module.ccall("ge_fromfe_frombytes_vartime", "void", ["number", "number"], [point_m, h_m]);
        //Module.ccall("ge_mul8", "void", ["number", "number"], [point2_m, point_m]);
        //Module.ccall("ge_p1p1_to_p3", "void", ["number", "number"], [res_m, point_m]);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [res2_m, point_m]);
        var res = Module.HEAPU8.subarray(res2_m, res2_m + KEY_SIZE);
        Module._free(h_m);
        Module._free(point_m);
        //Module._free(point2_m);
        //Module._free(res_m);
        Module._free(res2_m);
        return bintohex(res);
    };

    this.generate_key_image_2 = function(pub, sec) {
        if (!pub || !sec || pub.length !== 64 || sec.length !== 64) {
            throw "Invalid input length";
        }
        var pub_m = Module._malloc(KEY_SIZE);
        var sec_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(pub), pub_m);
        Module.HEAPU8.set(hextobin(sec), sec_m);
        if (Module.ccall("sc_check", "number", ["number"], [sec_m]) !== 0) {
            throw "sc_check(sec) != 0";
        }
        var point_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var point2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var point_b = hextobin(this.hash_to_ec(pub));
        Module.HEAPU8.set(point_b, point_m);
        var image_m = Module._malloc(STRUCT_SIZES.KEY_IMAGE);
        Module.ccall("ge_scalarmult", "void", ["number", "number", "number"], [point2_m, sec_m, point_m]);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [image_m, point2_m]);
        var res = Module.HEAPU8.subarray(image_m, image_m + STRUCT_SIZES.KEY_IMAGE);
        Module._free(pub_m);
        Module._free(sec_m);
        Module._free(point_m);
        Module._free(point2_m);
        Module._free(image_m);
        return bintohex(res);
    };

    this.generate_key_image = function(tx_pub, view_sec, spend_pub, spend_sec, output_index) {
        if (tx_pub.length !== 64) {
            throw "Invalid tx_pub length";
        }
        if (view_sec.length !== 64) {
            throw "Invalid view_sec length";
        }
        if (spend_pub.length !== 64) {
            throw "Invalid spend_pub length";
        }
        if (spend_sec.length !== 64) {
            throw "Invalid spend_sec length";
        }
        var recv_derivation = this.generate_key_derivation(tx_pub, view_sec);
        var ephemeral_pub = this.derive_public_key(recv_derivation, output_index, spend_pub);
        var ephemeral_sec = this.derive_secret_key(recv_derivation, output_index, spend_sec);
        var k_image = this.generate_key_image_2(ephemeral_pub, ephemeral_sec);
        return {
            ephemeral_pub: ephemeral_pub,
            key_image: k_image
        };
    };

    this.generate_key_image_helper = function(keys, tx_pub_key, out_index) {
        var recv_derivation = this.generate_key_derivation(tx_pub_key, keys.view.sec);
        if (!recv_derivation) throw "Failed to generate key image";
        var ephemeral_pub = this.derive_public_key(recv_derivation, out_index, keys.spend.pub);
        if (!ephemeral_pub) throw "Failed to generate key image";
        var ephemeral_sec = this.derive_secret_key(recv_derivation, out_index, keys.spend.sec);
        var image = this.generate_key_image_2(ephemeral_pub, ephemeral_sec);
        return {
            in_ephemeral: {
                pub: ephemeral_pub,
                sec: ephemeral_sec
            },
            image: image
        };
    };

    //curve and scalar functions; split out to make their host functions cleaner and more readable
    //inverts X coordinate -- this seems correct ^_^ -luigi1111
    this.ge_neg = function(point) {
      if (point.length !== 64){
        throw "expected 64 char hex string";
      }
      return point.slice(0,62) + ((parseInt(point.slice(62,63), 16) + 8) % 16).toString(16) + point.slice(63,64);
    };

    //adds two points together, order does not matter
    this.ge_add = function(point1, point2) {
        var point1_m = Module._malloc(KEY_SIZE);
        var point2_m = Module._malloc(KEY_SIZE);
        var point1_m2 = Module._malloc(STRUCT_SIZES.GE_P3);
        var point2_m2 = Module._malloc(STRUCT_SIZES.GE_P3);
        Module.HEAPU8.set(hextobin(point1), point1_m);
        Module.HEAPU8.set(hextobin(point2), point2_m);
        if (Module.ccall("ge_frombytes_vartime", "bool", ["number", "number"], [point1_m2, point1_m]) !== 0) {
            throw "ge_frombytes_vartime returned non-zero error code";
        }
        if (Module.ccall("ge_frombytes_vartime", "bool", ["number", "number"], [point2_m2, point2_m]) !== 0) {
            throw "ge_frombytes_vartime returned non-zero error code";
        }
        var sum_m = Module._malloc(KEY_SIZE);
        var p2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var p1_m = Module._malloc(STRUCT_SIZES.GE_P1P1);
        var p3_m = Module._malloc(STRUCT_SIZES.GE_CACHED);
        Module.ccall("ge_p3_to_cached", "void", ["number", "number"], [p3_m, point2_m2]);
        Module.ccall("ge_add", "void", ["number", "number", "number"], [p1_m, point1_m2, p3_m]);
        Module.ccall("ge_p1p1_to_p2", "void", ["number", "number"], [p2_m, p1_m]);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [sum_m, p2_m]);
        var res = Module.HEAPU8.subarray(sum_m, sum_m + KEY_SIZE);
        Module._free(point1_m);
        Module._free(point1_m2);
        Module._free(point2_m);
        Module._free(point2_m2);
        Module._free(p2_m);
        Module._free(p1_m);
        Module._free(sum_m);
        Module._free(p3_m);
        return bintohex(res);
    };

    //order matters
    this.ge_sub = function(point1, point2) {
        point2n = ge_neg(point2);
        return ge_add(point1, point2n);
    };

    //adds two scalars together
    this.sc_add = function(scalar1, scalar2) {
        if (scalar1.length !== 64 || scalar2.length !== 64) {
            throw "Invalid input length!";
        }
        var scalar1_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var scalar2_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        Module.HEAPU8.set(hextobin(scalar1), scalar1_m);
        Module.HEAPU8.set(hextobin(scalar2), scalar2_m);
        var derived_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        Module.ccall("sc_add", "void", ["number", "number", "number"], [derived_m, scalar1_m, scalar2_m]);
        var res = Module.HEAPU8.subarray(derived_m, derived_m + STRUCT_SIZES.EC_SCALAR);
        Module._free(scalar1_m);
        Module._free(scalar2_m);
        Module._free(derived_m);
        return bintohex(res);
    };

    //subtracts one scalar from another
    this.sc_sub = function(scalar1, scalar2) {
        if (scalar1.length !== 64 || scalar2.length !== 64) {
            throw "Invalid input length!";
        }
        var scalar1_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var scalar2_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        Module.HEAPU8.set(hextobin(scalar1), scalar1_m);
        Module.HEAPU8.set(hextobin(scalar2), scalar2_m);
        var derived_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        Module.ccall("sc_sub", "void", ["number", "number", "number"], [derived_m, scalar1_m, scalar2_m]);
        var res = Module.HEAPU8.subarray(derived_m, derived_m + STRUCT_SIZES.EC_SCALAR);
        Module._free(scalar1_m);
        Module._free(scalar2_m);
        Module._free(derived_m);
        return bintohex(res);
    };

    //fun mul function
    this.sc_mul = function(scalar1, scalar2) {
        if (scalar1.length !== 64 || scalar2.length !== 64) {
            throw "Invalid input length!";
        }
        return d2s(JSBigInt(s2d(scalar1)).multiply(JSBigInt(s2d(scalar2))).remainder(l).toString());
    };

    //res = c - (ab) mod l; argument names copied from the signature implementation
    this.sc_mulsub = function(sigc, sec, k) {
        if (k.length !== KEY_SIZE * 2 || sigc.length !== KEY_SIZE * 2 || sec.length !== KEY_SIZE * 2 || !this.valid_hex(k) || !this.valid_hex(sigc) || !this.valid_hex(sec)) {
            throw "bad scalar";
        }
        var sec_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(sec), sec_m);
        var sigc_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(sigc), sigc_m);
        var k_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(k), k_m);
        var res_m = Module._malloc(KEY_SIZE);

        Module.ccall("sc_mulsub", "void", ["number", "number", "number", "number"], [res_m, sigc_m, sec_m, k_m]);
        res = Module.HEAPU8.subarray(res_m, res_m + KEY_SIZE);
        Module._free(k_m);
        Module._free(sec_m);
        Module._free(sigc_m);
        Module._free(res_m);
        return bintohex(res);
    };

    //res = aB + cG; argument names copied from the signature implementation
    this.ge_double_scalarmult_base_vartime = function(sigc, pub, sigr) {
        var pub_m = Module._malloc(KEY_SIZE);
        var pub2_m = Module._malloc(STRUCT_SIZES.GE_P3);
        Module.HEAPU8.set(hextobin(pub), pub_m);
        if (Module.ccall("ge_frombytes_vartime", "void", ["number", "number"], [pub2_m, pub_m]) !== 0) {
            throw "Failed to call ge_frombytes_vartime";
        }
        var sigc_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(sigc), sigc_m);
        var sigr_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(sigr), sigr_m);
        if (Module.ccall("sc_check", "number", ["number"], [sigc_m]) !== 0 || Module.ccall("sc_check", "number", ["number"], [sigr_m]) !== 0) {
            throw "bad scalar(s)";
        }
        var tmp_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var res_m = Module._malloc(KEY_SIZE);
        Module.ccall("ge_double_scalarmult_base_vartime", "void", ["number", "number", "number", "number"], [tmp_m, sigc_m, pub2_m, sigr_m]);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [res_m, tmp_m]);
        var res = Module. HEAPU8.subarray(res_m, res_m + KEY_SIZE);
        Module._free(pub_m);
        Module._free(pub2_m);
        Module._free(sigc_m);
        Module._free(sigr_m);
        Module._free(tmp_m);
        Module._free(res_m);
        return bintohex(res);
    };

    //res = a * Hp(B) + c*D
    //res = sigr * Hp(pub) + sigc * k_image; argument names also copied from the signature implementation; note precomp AND hash_to_ec are done internally!!
    this.ge_double_scalarmult_postcomp_vartime = function(sigr, pub, sigc, k_image) {
        var image_m = Module._malloc(STRUCT_SIZES.KEY_IMAGE);
        Module.HEAPU8.set(hextobin(k_image), image_m);
        var image_unp_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var image_pre_m = Module._malloc(STRUCT_SIZES.GE_DSMP);
        var tmp3_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var sigr_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var sigc_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var tmp2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var res_m = Module._malloc(STRUCT_SIZES.EC_POINT);
        if (Module.ccall("ge_frombytes_vartime", "void", ["number", "number"], [image_unp_m, image_m]) !== 0) {
            throw "Failed to call ge_frombytes_vartime";
        }
        Module.ccall("ge_dsm_precomp", "void", ["number", "number"], [image_pre_m, image_unp_m]);
        var ec = this.hash_to_ec(pub);
        Module.HEAPU8.set(hextobin(ec), tmp3_m);
        Module.HEAPU8.set(hextobin(sigc), sigc_m);
        Module.HEAPU8.set(hextobin(sigr), sigr_m);
        Module.ccall("ge_double_scalarmult_precomp_vartime", "void", ["number", "number", "number", "number", "number"], [tmp2_m, sigr_m, tmp3_m, sigc_m, image_pre_m]);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [res_m, tmp2_m]);
        var res = Module. HEAPU8.subarray(res_m, res_m + STRUCT_SIZES.EC_POINT);
        Module._free(image_m);
        Module._free(image_unp_m);
        Module._free(image_pre_m);
        Module._free(tmp3_m);
        Module._free(sigr_m);
        Module._free(sigc_m);
        Module._free(tmp2_m);
        Module._free(res_m);
        return bintohex(res);
    };

    //begin RCT functions

    //xv: vector of secret keys, 1 per ring (nrings)
    //pm: matrix of pubkeys, indexed by size first
    //iv: vector of indexes, 1 per ring (nrings), can be a string
    //size: ring size
    //nrings: number of rings
    //extensible borromean signatures
    this.genBorromean = function(xv, pm, iv, size, nrings){
      if (xv.length !== nrings){
        throw "wrong xv length " + xv.length;
      }
      if (pm.length !== size){
        throw "wrong pm size " + pm.length;
      }
      for (var i = 0; i < pm.length; i++){
        if (pm[i].length !== nrings){
          throw "wrong pm[" + i + "] length " + pm[i].length;
        }
      }
      if (iv.length !== nrings){
        throw "wrong iv length " + iv.length;
      }
      for (var i = 0; i < iv.length; i++){
        if (iv[i] >= size){
          throw "bad indices value at: " + i + ": " + iv[i];
        }
      }
      //signature struct
      var bb = {
        s: [],
        ee: ""
      };
      //signature pubkey matrix
      var L = [];
      //add needed sub vectors (1 per ring size)
      for (var i = 0; i < size; i++){
        bb.s[i] = [];
        L[i] = [];
      }
      //compute starting at the secret index to the last row
      var index;
      var alpha = [];
      for (var i = 0; i < nrings; i++){
        index = parseInt(iv[i]);
        alpha[i] = random_scalar();
        L[index][i] = ge_scalarmult_base(alpha[i]);
        for (var j = index + 1; j < size; j++){
          bb.s[j][i] = random_scalar();
          var c = hash_to_scalar(L[j-1][i]);
          L[j][i] = ge_double_scalarmult_base_vartime(c, pm[j][i], bb.s[j][i]);
        }
      }
      //hash last row to create ee
      var ltemp = "";
      for (var i = 0; i < nrings; i++){
        ltemp += L[size-1][i];
      }
      bb.ee = hash_to_scalar(ltemp);
      //compute the rest from 0 to secret index
      for (var i = 0; i < nrings; i++){
        var cc = bb.ee
        for (var j = 0; j < indices[i]; j++){
          bb.s[j][i] = random_scalar();
          var LL = ge_double_scalarmult_base_vartime(cc, pm[j][i], bb.s[j][i]);
          cc = hash_to_scalar(LL);
        }
        bb.s[j][i] = sc_mulsub(xv[i], cc, alpha[i]);
      }
      return bb;
    };
    
    this.verBorromean = function(bb, pm){
      var Lv1 = "";
      for (var i = 0; i < bb.s[0].length; i++){
        var c = bb.ee;
        for (var j = 0; j < bb.s.length - 1; j++){
          var LL = ge_double_scalarmult_base_vartime(c, pm[j][i], bb.s[j][i]);
          c = hash_to_scalar(LL);
        }
        console.log(j);
        Lv1 += ge_double_scalarmult_base_vartime(c, pm[j][i], bb.s[j][i]);
      }
      var eeComputed = hash_to_scalar(Lv1);
      return (eeComputed === bb.ee);
    };
    
    //proveRange
    //proveRange gives C, and mask such that \sumCi = C
    //   c.f. http://eprint.iacr.org/2015/1098 section 5.1
    //   and Ci is a commitment to either 0 or s^i, i=0,...,n
    //   thus this proves that "amount" is in [0, s^n] (we assume s to be 4) (2 for now with v2 txes)
    //   mask is a such that C = aG + bH, and b = amount
    //commitMaskObj = {C: commit, mask: mask}
    this.proveRange = function(commitMaskObj, amount, nrings, enc_seed, exponent){
      var size = 2;
      var C = I; //identity
      var mask = Z; //zero scalar
      var indices = d2b(amount); //base 2 for now
      var sig = {
        Ci: []
        //exp: exponent //doesn't exist for now
      }
      /*payload stuff - ignore for now
      seeds = new Array(3);
      for (var i = 0; i < seeds.length; i++){
        seeds[i] = new Array(1);
      }
      genSeeds(seeds, enc_seed);
      */
      var ai = [];
      var PM = [];
      for (var i = 0; i < size; i++){
        PM[i] = [];
      }
      var j;
      //start at index and fill PM left and right -- PM[0] holds Ci
      for (i = 0; i < nrings; i++){
        ai[i] = random_scalar();
        j = indices[i];
        PM[j][i] = ge_scalarmult_base(ai[i]);
        while (j > 0){
          j--;
          PM[j][i] = ge_add(PM[j+1][i], H2[i]); //will need to use i*2 for base 4 (or different object)
        }
        j = indices[i];
        while (j < size - 1){
          j++;
          PM[j][i] = ge_sub(PM[j-1][i], H2[i]); //will need to use i*2 for base 4 (or different object)
        }
        mask = sc_add(mask, ai[i]);
      }
      /*
      * some more payload stuff here
      */
      //copy commitments to sig and sum them to commitment
      for (i = 0; i < nrings; i++){
        //if (i < nrings - 1) //for later version
        sig.Ci[i] = PM[0][i];
        C = ge_add(C, PM[0][i]);
      }
      /* exponent stuff - ignore for now
      if (exponent){
        n = JSBigInt(10);
        n = n.pow(exponent).toString();
        mask = sc_mul(mask, d2s(n)); //new sum
      }
      */
      sig.bsig = this.genBorromean(ai, PM, indices, size, nrings);
      commitMaskObj.C = C;
      commitMaskObj.mask = mask;
      return sig;
    };
    
    
    function array_hash_to_scalar(array){
      var buf = ""
      for (var i = 0; i < array.length; i++){
        if (typeof array[i] !== "string"){throw "unexpected array element";}
        buf += array[i];
      }
      return hash_to_scalar(buf);
    }
    
    // Gen creates a signature which proves that for some column in the keymatrix "pk"
    //   the signer knows a secret key for each row in that column
    // we only support matrices of 2 rows (pubkey, commitment)
    // because we don't want to force same secret column for all inputs
    this.MLSAG_Gen = function(message, pk, xx, kimg, index){
      var cols = pk.length; //ring size
      if (index >= cols){throw "index out of range";}
      var rows = pk[0].length; //number of signature rows (always 2)
      if (rows !== 2){throw "wrong row count";}
      for (var i = 0; i < cols; i++){
        if (pk[i].length !== rows){throw "pk is not rectangular";}
      }
      if (xx.length !== rows){throw "bad xx size";}
    
      var c_old = "";
      var alphas = [];
    
      var rv = {
        ss: [],
        cc: null,
      };
      for (i = 0; i < cols; i++){
        rv.ss[i] = [];
      }
      var toHash = []; //holds 6 elements: message, pubkey, dsRow L, dsRow R, commitment, ndsRow L
      toHash[0] = message;
      
      //secret index (pubkey section)
      alpha[0] = random_scalar(); //need to save alphas for later
      toHash[1] = pk[index][0]; //secret index pubkey
      toHash[2] = ge_scalarmult_base(alpha[0]); //dsRow L
      toHash[3] = generate_key_image_2(pk[index][0], alpha[0]); //dsRow R (key image check)
      //secret index (commitment section)
      alpha[1] = random_scalar();
      toHash[4] = pk[index][1]; //secret index commitment
      toHash[5] = ge_scalarmult_base(alpha[1]); //ndsRow L
    
      c_old = array_hash_to_scalar(toHash);
    
      i = (index + 1) % cols;
      if (i === 0){
        rv.cc = c_old;
      }
      while (i != index){
        rv.ss[i][0] = random_scalar(); //dsRow ss
        rv.ss[i][1] = random_scalar(); //ndsRow ss
    
        //!secret index (pubkey section)
        toHash[1] = pk[i][0];
        toHash[2] = ge_double_scalarmult_base_vartime(c_old, pk[i][0], rv.ss[i][0]);
        toHash[3] = ge_double_scalarmult_postcomp_vartime(rv.ss[i][0], pk[i][0], c_old, kimg);
        //!secret index (commitment section)
        toHash[4] = pk[i][1];
        toHash[5] = ge_double_scalarmult_base_vartime(c_old, pk[i][1], rv.ss[i][1]);
        c_old = array_hash_to_scalar(toHash); //hash to get next column c
        i = (i + 1) % cols;
        if (i === 0){
          rv.cc = c_old;
        }
      }
      for (i = 0; i < rows; i++){
        rv.ss[index][i] = sc_mulsub(c_old, xx[i], alpha[i]);
      }
      return rv;
    };
    
    //prepares for MLSAG_Gen
    this.proveRctMG = function(message, pubs, inSk, kimg, mask, Cout, index){
      var cols = pubs.length;
      if (cols < 3){throw "cols must be > 2 (mixin)";}
      var xx = [];
      var PK = [
        [],
        []
      ];
      //fill pubkey matrix (copy destination, subtract commitments)
      for (var i = 0; i < cols; i++){
        PK[i][0] = pubs[i].dest;
        PK[i][1] = ge_sub(pubs[i].mask, Cout);
      }
      xx[0] = inSk.x;
      xx[1] = sc_sub(inSk.a, mask);
      return this.MLSAG_Gen(message, PK, xx, kimg, index);
    };
    
    //message is normal prefix hash
    //inSk is vector of x,a
    //kimg is vector of kimg
    //destinations is vector of pubkeys
    //inAmounts is vector of strings
    //outAmounts is vector of strings
    //mixRing is matrix of pubkey, commit (dest, mask)
    //amountKeys is vector of scalars
    //indices is vector
    //txnFee is string
    this.genRct = function(message, inSk, kimg, destinations, inAmounts, outAmounts, mixRing, amountKeys, indices, txnFee){
      if (outAmounts.length !== destinations.length || amountKeys.length !== destinations.length){throw "different number of amounts/amount_keys vs destinations";}
      for (var i = 0; i < mixRing.length; i++){
        if (mixRing[i].length >= indices[i]){throw "bad mixRing/index size";}
        if (mixRing[i].length !== inSk.length){throw "mismatched mixRing/inSk";}
      }
      if (inAmounts.length !== inSk.length){throw "mismatched inAmounts/inSk";}
      if (indices.length !== inSk.length){throw "mismatched indices/inSk";}
      
      rv = {
        type: inSk.length === 1 ? 1 : 2,
        message: message,
        outPk: [],
        p: {
          rangeSigs: [],
          MGs: []
        },
        ecdhInfo: [],
        txnFee: txnFee,
        pseudoOuts: []
      };
      
      var sumout = Z;
      var cmObj = {
        C: null,
        mask: null,
      };
      var nrings = 64; //for base 2/current
      //compute range proofs, etc
      for (i = 0; i < destinations.length; i++){
        rv.p.rangeSigs[i] = this.proveRange(cmObj, outAmounts[i], nrings, 0, 0);
        rv.outPk[i] = cmObj.C;
        sumout = sc_add(sumout, cmObj.mask);
        rv.ecdhInfo[i] = {
          mask: sc_add(hash_to_scalar(amountKeys), cmObj.mask),
          amount: sc_add(hash_to_scalar(hash_to_scalar(amountKeys)), d2s(outAmounts[i]))
        };
      }
    
      //simple
      if (rv.type === 2){
        var ai = [];
        var sumpouts = Z;
        //create pseudoOuts
        for (i = 0; i < inAmounts.length - 1; i++){
          ai[i] = random_scalar();
          sumpouts = sc_add(sumpouts, ai[i]);
          rv.pseudoOuts[i] = commit(d2s(inAmounts[i]), ai[i]);
        }
        ai[i] = sc_sub(sumout, sumpouts);
        rv.pseudoOuts[i] = commit(d2s(inAmounts[i]), ai[i]);
        var full_message = get_pre_mlsag_hash(rv);
        for (i = 0; i < inAmounts.length; i++){
          rv.p.MGs[i] = this.proveRctMG(full_message, pubs[i], inSk[i], kimg[i], ai[i], rv.pseudoOuts[i], indices[i]);
        }
      } else {
        var sumC = I;
        //get sum of output commitments to use in MLSAG
        for (i = 0; i < destinations.length; i++){
          sumC = ge_add(sumC, rv.outPk[i]);
        }
        sumC = ge_add(sumC, ge_scalarmult(H, d2s(txnFee)));
        var full_message = get_pre_mlsag_hash(rv);
        rv.p.MGs.push = this.proveRctMG(full_message, pubs[0], inSk[0], kimg[0], sumout, sumC, indices[0]);
      }
      return rv;
    };

    //end RCT functions


    this.add_pub_key_to_extra = function(extra, pubkey) {
        if (pubkey.length !== 64) throw "Invalid pubkey length";
        // Append pubkey tag and pubkey
        extra += TX_EXTRA_TAGS.PUBKEY + pubkey;
        return extra;
    };

    this.add_nonce_to_extra = function(extra, nonce) {
        // Append extra nonce
        if ((nonce.length % 2) !== 0) {
            throw "Invalid extra nonce";
        }
        if ((nonce.length / 2) > TX_EXTRA_NONCE_MAX_COUNT) {
            throw "Extra nonce must be at most " + TX_EXTRA_NONCE_MAX_COUNT + " bytes";
        }
        // Add nonce tag
        extra += TX_EXTRA_TAGS.NONCE;
        // Encode length of nonce
        extra += ('0' + (nonce.length / 2).toString(16)).slice(-2);
        // Write nonce
        extra += nonce;
        return extra;
    };

    this.get_payment_id_nonce = function(payment_id, pid_encrypt) {
        if (payment_id.length !== 64 && payment_id.length !== 16) {
            throw "Invalid payment id";
        }
        var res = '';
        if (pid_encrypt) {
            res += TX_EXTRA_NONCE_TAGS.ENCRYPTED_PAYMENT_ID;
        } else {
            res += TX_EXTRA_NONCE_TAGS.PAYMENT_ID;
        }
        res += payment_id;
        return res;
    };

    this.abs_to_rel_offsets = function(offsets) {
        if (offsets.length === 0) return offsets;
        for (var i = offsets.length - 1; i >= 1; --i) {
            offsets[i] = new JSBigInt(offsets[i]).subtract(offsets[i - 1]).toString();
        }
        return offsets;
    };

    this.get_tx_prefix_hash = function(tx) {
        var prefix = this.serialize_tx(tx, true);
        return this.cn_fast_hash(prefix);
    };

    this.get_tx_hash = function(tx) {
        if (typeof(tx) === 'string') {
            return this.cn_fast_hash(tx);
        } else {
            return this.cn_fast_hash(this.serialize_tx(tx));
        }
    };

    this.serialize_tx = function(tx, headeronly) {
        //tx: {
        //  version: uint64,
        //  unlock_time: uint64,
        //  extra: hex,
        //  vin: [{amount: uint64, k_image: hex, key_offsets: [uint64,..]},...],
        //  vout: [{amount: uint64, target: {key: hex}},...],
        //  signatures: [[s,s,...],...]
        //}
        if (headeronly === undefined) {
            headeronly = false;
        }
        var buf = "";
        buf += this.encode_varint(tx.version);
        buf += this.encode_varint(tx.unlock_time);
        buf += this.encode_varint(tx.vin.length);
        var i, j;
        for (i = 0; i < tx.vin.length; i++) {
            var vin = tx.vin[i];
            switch (vin.type) {
                case "input_to_key":
                    buf += "02";
                    buf += this.encode_varint(vin.amount);
                    buf += this.encode_varint(vin.key_offsets.length);
                    for (j = 0; j < vin.key_offsets.length; j++) {
                        buf += this.encode_varint(vin.key_offsets[j]);
                    }
                    buf += vin.k_image;
                    break;
                default:
                    throw "Unhandled vin type: " + vin.type;
            }
        }
        buf += this.encode_varint(tx.vout.length);
        for (i = 0; i < tx.vout.length; i++) {
            var vout = tx.vout[i];
            buf += this.encode_varint(vout.amount);
            switch (vout.target.type) {
                case "txout_to_key":
                    buf += "02";
                    buf += vout.target.key;
                    break;
                default:
                    throw "Unhandled txout target type: " + vout.target.type;
            }
        }
        if (!this.valid_hex(tx.extra)) {
            throw "Tx extra has invalid hex";
        }
        buf += this.encode_varint(tx.extra.length / 2);
        buf += tx.extra;
        if (!headeronly) {
            if (tx.vin.length !== tx.signatures.length) {
                throw "Signatures length != vin length";
            }
            for (i = 0; i < tx.vin.length; i++) {
                for (j = 0; j < tx.signatures[i].length; j++) {
                    buf += tx.signatures[i][j];
                }
            }
        }
        return buf;
    };

    // basic signature impl based on that found in crypto.cpp; standard Schnorr, not EdDSA, and uses random k
    /* old version --this.generate_signature = function(prefix_hash, pub, sec) {
        if (sec.length !== KEY_SIZE * 2) {
            throw "Invalid secret key length";
        }
        if (prefix_hash.length !== HASH_SIZE * 2 || !this.valid_hex(prefix_hash)) {
            throw "Invalid prefix hash";
        }
        var k_m = Module._malloc(KEY_SIZE);
        var sec_m = Module._malloc(KEY_SIZE);
        var sigc_m = Module._malloc(STRUCT_SIZES.SIGNATURE / 2);
        var sigr_m = Module._malloc(STRUCT_SIZES.SIGNATURE / 2);
        var k = this.random_scalar();
        var comm = this.sec_key_to_pub(k);
        var sig = {};
        sig.c = this.hash_to_scalar(prefix_hash + pub + comm);
        Module.HEAPU8.set(hextobin(k), k_m);
        Module.HEAPU8.set(hextobin(sec), sec_m);
        Module.HEAPU8.set(hextobin(sig.c), sigc_m);
        Module.ccall("sc_mulsub", "void", ["number", "number", "number", "number"], [sigr_m, sigc_m, sec_m, k_m]);
        sig.r = bintohex(Module.HEAPU8.subarray(sigr_m, sigr_m + KEY_SIZE));
        Module._free(k_m);
        Module._free(sec_m);
        Module._free(sigc_m);
        Module._free(sigr_m);
        return sig.c + sig.r;
    };*/

    this.generate_signature = function(prefix_hash, pub, sec) {
        if (sec.length !== KEY_SIZE * 2 || !this.valid_hex(sec)) {
            throw "Invalid secret key";
        }
        if (prefix_hash.length !== HASH_SIZE * 2 || !this.valid_hex(prefix_hash)) {
            throw "Invalid prefix hash";
        }
        var k = this.random_scalar();
        var comm = this.sec_key_to_pub(k);
        var c = this.hash_to_scalar(prefix_hash + pub + comm);
        var r = this.sc_mulsub(c, sec, k);
        return c + r;
    };

/* old version
    this.check_signature = function(prefix_hash, pub, signature) {
        if (signature.length !== STRUCT_SIZES.SIGNATURE * 2) {
            throw "Invalid signature length";
        }
        if (prefix_hash.length !== HASH_SIZE * 2 || !this.valid_hex(prefix_hash)) {
            throw "Invalid prefix hash";
        }
        var sig = {};
        sig.c = signature.slice(0, STRUCT_SIZES.SIGNATURE);
        sig.r = signature.slice(STRUCT_SIZES.SIGNATURE, STRUCT_SIZES.SIGNATURE * 2);
        var sigc_m = Module._malloc(STRUCT_SIZES.SIGNATURE / 2);
        var sigr_m = Module._malloc(STRUCT_SIZES.SIGNATURE / 2);
        var pub_m = Module._malloc(KEY_SIZE);
        var tmp3_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var tmp2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var comm_m = Module._malloc(KEY_SIZE);
        var c_m = Module._malloc(STRUCT_SIZES.SIGNATURE / 2);
        Module.HEAPU8.set(hextobin(sig.c), sigc_m);
        Module.HEAPU8.set(hextobin(sig.r), sigr_m);
        Module.HEAPU8.set(hextobin(pub), pub_m);
        if (Module.ccall("ge_frombytes_vartime", "void", ["number", "number"], [tmp3_m, pub_m]) !== 0) {
            throw "Failed to call ge_frombytes_vartime";
        }
        if (Module.ccall("sc_check", "number", ["number"], [sigc_m]) !== 0 || Module.ccall("sc_check", "number", ["number"], [sigr_m]) !== 0) {
            return false;
        }
        Module.ccall("ge_double_scalarmult_base_vartime", "void", ["number", "number", "number", "number"], [tmp2_m, sigc_m, tmp3_m, sigr_m]);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [comm_m, tmp2_m]);
        var comm = bintohex(Module.HEAPU8.subarray(comm_m, comm_m + KEY_SIZE));
        var c = this.hash_to_scalar(prefix_hash + pub + comm);
        Module._free(sigc_m);
        Module._free(sigr_m);
        Module._free(pub_m);
        Module._free(tmp3_m);
        Module._free(tmp2_m);
        Module._free(comm_m);
        Module._free(c_m);
        return (sig.c === c);
    };*/

    this.check_signature = function(prefix_hash, pub, signature) {
        if (signature.length !== STRUCT_SIZES.SIGNATURE * 2) {
            return false;
        }
        if (prefix_hash.length !== HASH_SIZE * 2 || !this.valid_hex(prefix_hash)) {
            throw "Invalid prefix hash";
        }
        var sig = {};
        sig.c = signature.slice(0, STRUCT_SIZES.SIGNATURE);
        sig.r = signature.slice(STRUCT_SIZES.SIGNATURE, STRUCT_SIZES.SIGNATURE * 2);
        try{
            var comm = this.ge_double_scalarmult_base_vartime(sig.c, pub, sig.r);
        } catch (err) {
            return false;
        }
        var c = this.hash_to_scalar(prefix_hash + pub + comm);
        return (sig.c === c);
    };

    this.generate_ring_signature = function(prefix_hash, k_image, keys, sec, real_index) {
        if (k_image.length !== STRUCT_SIZES.KEY_IMAGE * 2) {
            throw "invalid key image length";
        }
        if (sec.length !== KEY_SIZE * 2) {
            throw "Invalid secret key length";
        }
        if (prefix_hash.length !== HASH_SIZE * 2 || !this.valid_hex(prefix_hash)) {
            throw "Invalid prefix hash";
        }
        if (real_index >= keys.length || real_index < 0) {
            throw "real_index is invalid";
        }
        var _ge_tobytes = Module.cwrap("ge_tobytes", "void", ["number", "number"]);
        var _ge_p3_tobytes = Module.cwrap("ge_p3_tobytes", "void", ["number", "number"]);
        var _ge_scalarmult_base = Module.cwrap("ge_scalarmult_base", "void", ["number", "number"]);
        var _ge_scalarmult = Module.cwrap("ge_scalarmult", "void", ["number", "number", "number"]);
        var _sc_add = Module.cwrap("sc_add", "void", ["number", "number", "number"]);
        var _sc_sub = Module.cwrap("sc_sub", "void", ["number", "number", "number"]);
        var _sc_mulsub = Module.cwrap("sc_mulsub", "void", ["number", "number", "number", "number"]);
        var _sc_0 = Module.cwrap("sc_0", "void", ["number"]);
        var _ge_double_scalarmult_base_vartime = Module.cwrap("ge_double_scalarmult_base_vartime", "void", ["number", "number", "number", "number"]);
        var _ge_double_scalarmult_precomp_vartime = Module.cwrap("ge_double_scalarmult_precomp_vartime", "void", ["number", "number", "number", "number", "number"]);
        var _ge_frombytes_vartime = Module.cwrap("ge_frombytes_vartime", "number", ["number", "number"]);
        var _ge_dsm_precomp = Module.cwrap("ge_dsm_precomp", "void", ["number", "number"]);

        var buf_size = STRUCT_SIZES.EC_POINT * 2 * keys.length;
        var buf_m = Module._malloc(buf_size);
        var sig_size = STRUCT_SIZES.SIGNATURE * keys.length;
        var sig_m = Module._malloc(sig_size);

        // Struct pointer helper functions
        function buf_a(i) {
            return buf_m + STRUCT_SIZES.EC_POINT * (2 * i);
        }
        function buf_b(i) {
            return buf_m + STRUCT_SIZES.EC_POINT * (2 * i + 1);
        }
        function sig_c(i) {
            return sig_m + STRUCT_SIZES.EC_SCALAR * (2 * i);
        }
        function sig_r(i) {
            return sig_m + STRUCT_SIZES.EC_SCALAR * (2 * i + 1);
        }
        var image_m = Module._malloc(STRUCT_SIZES.KEY_IMAGE);
        Module.HEAPU8.set(hextobin(k_image), image_m);
        var i;
        var image_unp_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var image_pre_m = Module._malloc(STRUCT_SIZES.GE_DSMP);
        var sum_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var k_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var h_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var tmp2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var tmp3_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var pub_m = Module._malloc(KEY_SIZE);
        var sec_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(sec), sec_m);
        if (_ge_frombytes_vartime(image_unp_m, image_m) != 0) {
            throw "failed to call ge_frombytes_vartime";
        }
        _ge_dsm_precomp(image_pre_m, image_unp_m);
        _sc_0(sum_m);
        for (i = 0; i < keys.length; i++) {
            if (i === real_index) {
                // Real key
                var rand = this.random_scalar();
                Module.HEAPU8.set(hextobin(rand), k_m);
                _ge_scalarmult_base(tmp3_m, k_m);
                _ge_p3_tobytes(buf_a(i), tmp3_m);
                var ec = this.hash_to_ec(keys[i]);
                Module.HEAPU8.set(hextobin(ec), tmp3_m);
                _ge_scalarmult(tmp2_m, k_m, tmp3_m);
                _ge_tobytes(buf_b(i), tmp2_m);
            } else {
                Module.HEAPU8.set(hextobin(this.random_scalar()), sig_c(i));
                Module.HEAPU8.set(hextobin(this.random_scalar()), sig_r(i));
                Module.HEAPU8.set(hextobin(keys[i]), pub_m);
                if (Module.ccall("ge_frombytes_vartime", "void", ["number", "number"], [tmp3_m, pub_m]) !== 0) {
                    throw "Failed to call ge_frombytes_vartime";
                }
                _ge_double_scalarmult_base_vartime(tmp2_m, sig_c(i), tmp3_m, sig_r(i));
                _ge_tobytes(buf_a(i), tmp2_m);
                var ec = this.hash_to_ec(keys[i]);
                Module.HEAPU8.set(hextobin(ec), tmp3_m);
                _ge_double_scalarmult_precomp_vartime(tmp2_m, sig_r(i), tmp3_m, sig_c(i), image_pre_m);
                _ge_tobytes(buf_b(i), tmp2_m);
                _sc_add(sum_m, sum_m, sig_c(i));
            }
        }
        var buf_bin = Module.HEAPU8.subarray(buf_m, buf_m + buf_size);
        var scalar = this.hash_to_scalar(prefix_hash + bintohex(buf_bin));
        Module.HEAPU8.set(hextobin(scalar), h_m);
        _sc_sub(sig_c(real_index), h_m, sum_m);
        _sc_mulsub(sig_r(real_index), sig_c(real_index), sec_m, k_m);
        var sig_data = bintohex(Module.HEAPU8.subarray(sig_m, sig_m + sig_size));
        var sigs = [];
        for (var k = 0; k < keys.length; k++) {
            sigs.push(sig_data.slice(STRUCT_SIZES.SIGNATURE * 2 * k, STRUCT_SIZES.SIGNATURE * 2 * (k + 1)));
        }
        Module._free(image_m);
        Module._free(image_unp_m);
        Module._free(image_pre_m);
        Module._free(sum_m);
        Module._free(k_m);
        Module._free(h_m);
        Module._free(tmp2_m);
        Module._free(tmp3_m);
        Module._free(buf_m);
        Module._free(sig_m);
        Module._free(pub_m);
        Module._free(sec_m);
        return sigs;
    };

    this.check_ring_signature = function(prefix_hash, k_image, pubs, sigs) {
        if (k_image.length !== STRUCT_SIZES.KEY_IMAGE * 2) {
            throw "invalid key image length";
        }
        if (prefix_hash.length !== HASH_SIZE * 2 || !this.valid_hex(prefix_hash)) {
            throw "Invalid prefix hash";
        }
        if (sigs.length !== pubs.length) {
            throw "number of sigs doesn't match number of pubs";
        }
        var _ge_tobytes = Module.cwrap("ge_tobytes", "void", ["number", "number"]);
        var _ge_p3_tobytes = Module.cwrap("ge_p3_tobytes", "void", ["number", "number"]);
        var _sc_add = Module.cwrap("sc_add", "void", ["number", "number", "number"]);
        var _sc_0 = Module.cwrap("sc_0", "void", ["number"]);
        var _ge_double_scalarmult_base_vartime = Module.cwrap("ge_double_scalarmult_base_vartime", "void", ["number", "number", "number", "number"]);
        var _ge_double_scalarmult_precomp_vartime = Module.cwrap("ge_double_scalarmult_precomp_vartime", "void", ["number", "number", "number", "number", "number"]);
        var _ge_frombytes_vartime = Module.cwrap("ge_frombytes_vartime", "number", ["number", "number"]);
        var _ge_dsm_precomp = Module.cwrap("ge_dsm_precomp", "void", ["number", "number"]);
        
        var sigstr = sigs.join("");
        
        var buf_size = STRUCT_SIZES.EC_POINT * 2 * pubs.length;
        var buf_m = Module._malloc(buf_size);
        var sig_size = STRUCT_SIZES.SIGNATURE * pubs.length;
        var sig_m = Module._malloc(sig_size);

        function buf_a(i) {
            return buf_m + STRUCT_SIZES.EC_POINT * (2 * i);
        }
        function buf_b(i) {
            return buf_m + STRUCT_SIZES.EC_POINT * (2 * i + 1);
        }
        function sig_c(i) {
            return sig_m + STRUCT_SIZES.EC_SCALAR * (2 * i);
        }
        function sig_r(i) {
            return sig_m + STRUCT_SIZES.EC_SCALAR * (2 * i + 1);
        }
        
        Module.HEAPU8.set(hextobin(sigstr), sig_m);
        
        var image_m = Module._malloc(STRUCT_SIZES.KEY_IMAGE);
        Module.HEAPU8.set(hextobin(k_image), image_m);
        var image_unp_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var image_pre_m = Module._malloc(STRUCT_SIZES.GE_DSMP);
        var sum_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var tmp2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var tmp3_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var pub_m = Module._malloc(KEY_SIZE);
        if (_ge_frombytes_vartime(image_unp_m, image_m) != 0) {
            throw "failed to call ge_frombytes_vartime";
        }
        _ge_dsm_precomp(image_pre_m, image_unp_m);
        _sc_0(sum_m);
        for (var i = 0; i < pubs.length; i++) {
            if (Module.ccall("sc_check", "number", ["number"], [sig_c(i)]) !== 0 || Module.ccall("sc_check", "number", ["number"], [sig_r(i)]) !== 0) {
                console.log("bad sc");
                return false;
            }
            Module.HEAPU8.set(hextobin(pubs[i]), pub_m);
            if (Module.ccall("ge_frombytes_vartime", "void", ["number", "number"], [tmp3_m, pub_m]) !== 0) {
                throw "Failed to call ge_frombytes_vartime";
            }
            _ge_double_scalarmult_base_vartime(tmp2_m, sig_c(i), tmp3_m, sig_r(i));
            _ge_tobytes(buf_a(i), tmp2_m);
            var ec = this.hash_to_ec(pubs[i]);
            Module.HEAPU8.set(hextobin(ec), tmp3_m);
            _ge_double_scalarmult_precomp_vartime(tmp2_m, sig_r(i), tmp3_m, sig_c(i), image_pre_m);
            _ge_tobytes(buf_b(i), tmp2_m);
            _sc_add(sum_m, sum_m, sig_c(i));
        }
        var buf_bin = Module.HEAPU8.subarray(buf_m, buf_m + buf_size);
        var scalar = this.hash_to_scalar(prefix_hash + bintohex(buf_bin));
        var sum = bintohex(Module.HEAPU8.subarray(sum_m, sum_m + KEY_SIZE));
        Module._free(image_m);
        Module._free(image_unp_m);
        Module._free(image_pre_m);
        Module._free(sum_m);
        Module._free(tmp2_m);
        Module._free(tmp3_m);
        Module._free(buf_m);
        Module._free(sig_m);
        Module._free(pub_m);
        return (scalar === sum);
    };

    //attempt at using my functions for readability; prefix_hash is 32 bytes hex, k_image same, pubs is array of same, sigs is array of 64 bytes hex
    this.check_ring = function(prefix_hash, k_image, pubs, sigs) {
        if (k_image.length !== STRUCT_SIZES.KEY_IMAGE * 2) {
            console.log("invalid key image length");
            return false;
        }
        if (prefix_hash.length !== HASH_SIZE * 2 || !this.valid_hex(prefix_hash)) {
            console.log("Invalid prefix hash");
            return false;
        }
        if (sigs.length !== pubs.length) {
            console.log("number of sigs doesn't match number of pubs");
            return false;
        }
        var sigar = [];
        for (var i = 0; i < sigs.length; i++) {
            sigar[i] = {
            c: sigs[i].slice(0, 64),
            r: sigs[i].slice(64)
            };
        }
        var buf = prefix_hash;
        var sum = d2h256("0"); //zero, should add wrapper for sc_0
        for (var i = 0; i < pubs.length; i++) {
            try {
                buf += this.ge_double_scalarmult_base_vartime(sigar[i].c, pubs[i], sigar[i].r);
                buf += this.ge_double_scalarmult_postcomp_vartime(sigar[i].r, pubs[i], sigar[i].c, k_image);
                sum = sc_add(sum, sigar[i].c);
            } catch (err) {
                console.log(err);
                return false; //signature didn't verify (due to bad pubkeys or scalars)
            }
        }
        var comm_hash = hash_to_scalar(buf);
        return (sum === comm_hash);
    };

    this.construct_tx = function(keys, sources, dsts, fee_amount, payment_id, pid_encrypt, realDestViewKey, unlock_time) {
        //we move payment ID stuff here, because we need txkey to encrypt
        var txkey = this.random_keypair();
        var extra = '';
        if (payment_id) {
            if (pid_encrypt && payment_id.length !== INTEGRATED_ID_SIZE * 2) {
                throw "payment ID must be " + INTEGRATED_ID_SIZE + " bytes to be encrypted!";
            }
            console.log("Adding payment id: " + payment_id);
            if (pid_encrypt) { //get the derivation from our passed viewkey, then hash that + tail to get encryption key
                var pid_key = this.cn_fast_hash(this.generate_key_derivation(realDestViewKey, txkey.sec) + ENCRYPTED_PAYMENT_ID_TAIL.toString(16)).slice(0, INTEGRATED_ID_SIZE * 2);
                console.log("Txkeys:", txkey, "Payment ID key:", pid_key);
                payment_id = this.hex_xor(payment_id, pid_key);
            }
            var nonce = this.get_payment_id_nonce(payment_id, pid_encrypt);
            console.log("Extra nonce: " + nonce);
            extra = this.add_nonce_to_extra(extra, nonce);
        }
        var tx = {
            unlock_time: unlock_time,
            version: CURRENT_TX_VERSION,
            extra: extra,
            vin: [],
            vout: [],
            signatures: []
        };

        tx.extra = this.add_pub_key_to_extra(tx.extra, txkey.pub);

        var in_contexts = [];
        var inputs_money = JSBigInt.ZERO;
        var i, j;
        console.log('Sources: ');
        for (i = 0; i < sources.length; i++) {
            console.log(i + ': ' + this.formatMoneyFull(sources[i].amount));
            if (sources[i].real_out >= sources[i].outputs.length) {
                throw "real index >= outputs.length";
            }
            inputs_money = inputs_money.add(sources[i].amount);
            var res = this.generate_key_image_helper(keys, sources[i].real_out_tx_key, sources[i].real_out_in_tx);
            in_contexts.push(res.in_ephemeral);
            if (res.in_ephemeral.pub !== sources[i].outputs[sources[i].real_out].key) {
                throw "in_ephemeral.pub != source.real_out.key";
            }
            var input_to_key = {};
            input_to_key.type = "input_to_key";
            input_to_key.amount = sources[i].amount;
            input_to_key.k_image = res.image;
            input_to_key.key_offsets = [];
            for (j = 0; j < sources[i].outputs.length; ++j) {
                input_to_key.key_offsets.push(sources[i].outputs[j].index);
            }
            input_to_key.key_offsets = this.abs_to_rel_offsets(input_to_key.key_offsets);
            tx.vin.push(input_to_key);
        }
        var outputs_money = JSBigInt.ZERO;
        var out_index = 0;
        for (i = 0; i < dsts.length; ++i) {
            if (new JSBigInt(dsts[i].amount).compare(0) !== 1) {
                throw "dst.amount <= 0";
            }
            dsts[i].keys = this.decode_address(dsts[i].address);
            var out_derivation = this.generate_key_derivation(dsts[i].keys.view, txkey.sec);
            var out_ephemeral_pub = this.derive_public_key(out_derivation, out_index, dsts[i].keys.spend);
            var out = {
                amount: dsts[i].amount.toString()
            };
            // txout_to_key
            out.target = {
                type: "txout_to_key",
                key: out_ephemeral_pub
            };
            tx.vout.push(out);
            ++out_index;
            outputs_money = outputs_money.add(dsts[i].amount);
        }
        if (outputs_money.add(fee_amount).compare(inputs_money) > 0) {
            throw "outputs money (" + this.formatMoneyFull(outputs_money) + ") + fee (" + this.formatMoneyFull(fee_amount) + ") > inputs money (" + this.formatMoneyFull(inputs_money) + ")";
        }
        var tx_prefix_hash = this.get_tx_prefix_hash(tx);
        for (i = 0; i < sources.length; ++i) {
            var src_keys = [];
            for (j = 0; j < sources[i].outputs.length; ++j) {
                src_keys.push(sources[i].outputs[j].key);
            }
            var sigs = this.generate_ring_signature(tx_prefix_hash, tx.vin[i].k_image, src_keys,
                in_contexts[i].sec, sources[i].real_out);
            tx.signatures.push(sigs);
        }
        return tx;
    };

    this.create_transaction = function(pub_keys, sec_keys, dsts, outputs, mix_outs, fake_outputs_count, fee_amount, payment_id, pid_encrypt, realDestViewKey, unlock_time) {
        unlock_time = unlock_time || 0;
        mix_outs = mix_outs || [];
        var i, j;
        if (dsts.length === 0) {
            throw 'Destinations empty';
        }
        if (mix_outs.length !== outputs.length && fake_outputs_count !== 0) {
            throw 'Wrong number of mix outs provided (' + outputs.length + ' outputs, ' + mix_outs.length + ' mix outs)';
        }
        for (i = 0; i < mix_outs.length; i++) {
            if ((mix_outs[i].outputs || []).length < fake_outputs_count) {
                throw 'Not enough outputs to mix with';
            }
        }
        var keys = {
            view: {
                pub: pub_keys.view,
                sec: sec_keys.view
            },
            spend: {
                pub: pub_keys.spend,
                sec: sec_keys.spend
            }
        };
        if (!this.valid_keys(keys.view.pub, keys.view.sec, keys.spend.pub, keys.spend.sec)) {
            throw "Invalid secret keys!";
        }
        var needed_money = JSBigInt.ZERO;
        for (i = 0; i < dsts.length; ++i) {
            needed_money = needed_money.add(dsts[i].amount);
            if (needed_money.compare(UINT64_MAX) !== -1) {
                throw "Output overflow!";
            }
        }
        var found_money = JSBigInt.ZERO;
        var sources = [];
        console.log('Selected transfers: ', outputs);
        for (i = 0; i < outputs.length; ++i) {
            found_money = found_money.add(outputs[i].amount);
            if (found_money.compare(UINT64_MAX) !== -1) {
                throw "Input overflow!";
            }
            var src = {
                outputs: []
            };
            src.amount = new JSBigInt(outputs[i].amount).toString();
            if (mix_outs.length !== 0) {
                // Sort fake outputs by global index
                mix_outs[i].outputs.sort(function(a, b) {
                    return new JSBigInt(a.global_index).compare(b.global_index);
                });
                j = 0;
                while ((src.outputs.length < fake_outputs_count) && (j < mix_outs[i].outputs.length)) {
                    var out = mix_outs[i].outputs[j];
                    if (out.global_index === outputs[i].global_index) {
                        console.log('got mixin the same as output, skipping');
                        j++;
                        continue;
                    }
                    var oe = {};
                    oe.index = out.global_index.toString();
                    oe.key = out.public_key;
                    src.outputs.push(oe);
                    j++;
                }
            }
            var real_oe = {};
            real_oe.index = new JSBigInt(outputs[i].global_index || 0).toString();
            real_oe.key = outputs[i].public_key;
            var real_index = src.outputs.length;
            for (j = 0; j < src.outputs.length; j++) {
                if (new JSBigInt(real_oe.index).compare(src.outputs[j].index) < 0) {
                    real_index = j;
                    break;
                }
            }
            // Add real_oe to outputs
            src.outputs.splice(real_index, 0, real_oe);
            src.real_out_tx_key = outputs[i].tx_pub_key;
            // Real output entry index
            src.real_out = real_index;
            src.real_out_in_tx = outputs[i].index;
            sources.push(src);
        }
        console.log('sources: ', sources);
        var change = {
            amount: JSBigInt.ZERO
        };
        var cmp = needed_money.compare(found_money);
        if (cmp < 0) {
            change.amount = found_money.subtract(needed_money);
        } else if (cmp > 0) {
            throw "Need more money than found! (have: " + cnUtil.formatMoney(found_money) + " need: " + cnUtil.formatMoney(needed_money) + ")";
        }
        return this.construct_tx(keys, sources, dsts, fee_amount, payment_id, pid_encrypt, realDestViewKey, unlock_time);
    };

    function trimRight(str, char) {
        while (str[str.length - 1] == char) str = str.slice(0, -1);
        return str;
    }

    function padLeft(str, len, char) {
        while (str.length < len) {
            str = char + str;
        }
        return str;
    }

    this.printDsts = function(dsts) {
        for (var i = 0; i < dsts.length; i++) {
            console.log(dsts[i].address + ': ' + this.formatMoneyFull(dsts[i].amount));
        }
    };

    this.formatMoneyFull = function(units) {
        units = units.toString();
        var symbol = units[0] === '-' ? '-' : '';
        if (symbol === '-') {
            units = units.slice(1);
        }
        var decimal;
        if (units.length >= config.coinUnitPlaces) {
            decimal = units.substr(units.length - config.coinUnitPlaces, config.coinUnitPlaces);
        } else {
            decimal = padLeft(units, config.coinUnitPlaces, '0');
        }
        return symbol + (units.substr(0, units.length - config.coinUnitPlaces) || '0') + '.' + decimal;
    };

    this.formatMoneyFullSymbol = function(units) {
        return this.formatMoneyFull(units) + ' ' + config.coinSymbol;
    };

    this.formatMoney = function(units) {
        var f = trimRight(this.formatMoneyFull(units), '0');
        if (f[f.length - 1] === '.') {
            return f.slice(0, f.length - 1);
        }
        return f;
    };

    this.formatMoneySymbol = function(units) {
        return this.formatMoney(units) + ' ' + config.coinSymbol;
    };

    this.parseMoney = function(str) {
        if (!str) return JSBigInt.ZERO;
        var negative = str[0] === '-';
        if (negative) {
            str = str.slice(1);
        }
        var decimalIndex = str.indexOf('.');
        if (decimalIndex == -1) {
            if (negative) {
                return JSBigInt.multiply(str, config.coinUnits).negate();
            }
            return JSBigInt.multiply(str, config.coinUnits);
        }
        if (decimalIndex + config.coinUnitPlaces + 1 < str.length) {
            str = str.substr(0, decimalIndex + config.coinUnitPlaces + 1);
        }
        if (negative) {
            return new JSBigInt(str.substr(0, decimalIndex)).exp10(config.coinUnitPlaces)
                .add(new JSBigInt(str.substr(decimalIndex + 1)).exp10(decimalIndex + config.coinUnitPlaces - str.length + 1)).negate;
        }
        return new JSBigInt(str.substr(0, decimalIndex)).exp10(config.coinUnitPlaces)
            .add(new JSBigInt(str.substr(decimalIndex + 1)).exp10(decimalIndex + config.coinUnitPlaces - str.length + 1));
    };

    this.decompose_amount_into_digits = function(amount) {
        /*if (dust_threshold === undefined) {
            dust_threshold = config.dustThreshold;
        }*/
        amount = amount.toString();
        var ret = [];
        while (amount.length > 0) {
            //split all the way down since v2 fork
            /*var remaining = new JSBigInt(amount);
            if (remaining.compare(config.dustThreshold) <= 0) {
                if (remaining.compare(0) > 0) {
                    ret.push(remaining);
                }
                break;
            }*/
            //check so we don't create 0s
            if (amount[0] !== "0"){
                var digit = amount[0];
                while (digit.length < amount.length) {
                    digit += "0";
                }
                ret.push(new JSBigInt(digit));
            }
            amount = amount.slice(1);
        }
        return ret;
    };

    this.decompose_tx_destinations = function(dsts) {
        var out = [];
        for (var i = 0; i < dsts.length; i++) {
            var digits = this.decompose_amount_into_digits(dsts[i].amount);
            for (var j = 0; j < digits.length; j++) {
                if (digits[j].compare(0) > 0) {
                    out.push({
                        address: dsts[i].address,
                        amount: digits[j]
                    });
                }
            }
        }
        return out.sort(function(a,b){
            return a["amount"] - b["amount"];
        });
    };
 
    this.is_tx_unlocked = function(unlock_time, blockchain_height) {
        if (!config.maxBlockNumber) {
            throw "Max block number is not set in config!";
        }
        if (unlock_time < config.maxBlockNumber) {
            // unlock time is block height
            return blockchain_height >= unlock_time;
        } else {
            // unlock time is timestamp
            var current_time = Math.round(new Date().getTime() / 1000);
            return current_time >= unlock_time;
        }
    };

    this.tx_locked_reason = function(unlock_time, blockchain_height) {
        if (unlock_time < config.maxBlockNumber) {
            // unlock time is block height
            var numBlocks = unlock_time - blockchain_height;
            if (numBlocks <= 0) {
                return "Transaction is unlocked";
            }
            var unlock_prediction = moment().add(numBlocks * config.avgBlockTime, 'seconds');
            return "Will be unlocked in " + numBlocks + " blocks, ~" + unlock_prediction.fromNow(true) + ", " + unlock_prediction.calendar() + "";
        } else {
            // unlock time is timestamp
            var current_time = Math.round(new Date().getTime() / 1000);
            var time_difference = unlock_time - current_time;
            if(time_difference <= 0) {
                return "Transaction is unlocked";
            }
            var unlock_moment = moment(unlock_time * 1000);
            return "Will be unlocked " + unlock_moment.fromNow() + ", " + unlock_moment.calendar();
        }
    };

    function assert(stmt, val) {
        if (!stmt) {
            throw "assert failed" + (val !== undefined ? ': ' + val : '');
        }
    }

    return this;
})(config);
