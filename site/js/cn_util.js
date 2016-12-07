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

    //res = k - (sigc*sec); argument names copied from the signature implementation
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

    //res = sigc * pub + sigr * G; argument names also copied from the signature implementation
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

    //res = sigr * Hp(pub) + sigc * k_image; argument names also copied from the signature implementation; note precomp is done internally!
    this.ge_double_scalarmult_precomp_vartime = function(sigr, pub, sigc, k_image) {
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
        var sig = {};
        sig.c = this.hash_to_scalar(prefix_hash + pub + comm);
        sig.r = this.sc_mulsub(sig.c, sec, k);
        return sig.c + sig.r;
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

    this.check_signature2 = function(prefix_hash, pub, signature) {
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
