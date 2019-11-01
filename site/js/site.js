//functions for various XMR/Cryptonote stuff
//(c) 2016 luigi1111
//can't imagine this is useful for anything but this site, but
//Licensed under the MIT license:
//http://www.opensource.org/licenses/MIT

//requires cn_util.js, mnemonic.js, sha3.js, and their requirements

//document vars
var pubAddrNetByte,
paymentID, hexSeed,
privSpend, pubSpend,
privView, pubView,
pubAddr, mnemonic,
pubAddr2, validNo,
validYes,
extraInput, pubView2,
pubSpend2, pubAddrHex,
pubAddrChksum, pubAddrForHash,
pubAddrHash, pubAddrChksum2,
xmrAddr, resultsTag,
qr, payIdWrap,
private, addrTag,
txHash, typeTag, mnDictTag,
coinTypeTag, signMessageTag,
verifyMessageTag, verifyResultTag,
dataHashTag, keyImageTag,
keyImageResultsTag, encKeyTag,
encMnTag, encKey2Tag, addrPt2Tag,
derivedAddrTag, mnemonicPt2Tag,
derivedSpendKeyTag, derivedViewKeyTag,
encTypeTag;

var api = "https://moneroblocks.info/api/";

window.onload = function(){
    pubAddrNetByte = document.getElementById('pubAddrNetByte');
    paymentID = document.getElementById('paymentID');
    hexSeed = document.getElementById('hexSeed');
    privSpend = document.getElementById('privSpend');
    pubSpend = document.getElementById('pubSpend');
    privView = document.getElementById('privView');
    pubView = document.getElementById('pubView');
    pubAddr = document.getElementById('pubAddr');
    mnemonic = document.getElementById('mnemonic');
    pubAddr2 = document.getElementById('pubAddr2');
    validNo = document.getElementById('validNo');
    validYes = document.getElementById('validYes');
    extraInput = document.getElementById('extraInput');
    pubView2 = document.getElementById('pubView2');
    pubSpend2 = document.getElementById('pubSpend2');
    pubAddrHex = document.getElementById('pubAddrHex');
    pubAddrChksum = document.getElementById('pubAddrChksum');
    pubAddrForHash = document.getElementById('pubAddrForHash');
    pubAddrHash = document.getElementById('pubAddrHash');
    pubAddrChksum2 = document.getElementById('pubAddrChksum2');
    xmrAddr = document.getElementById('xmrAddr');
    resultsTag = document.getElementById('results');
    qrTag = document.getElementById('qr');
    payIdWrap = document.getElementById('payIdWrap');
    private = document.getElementById('private');
    addrTag = document.getElementById('addr');
    txHash = document.getElementById('txHash');
    typeTag = document.getElementById('type');
    coinTypeTag = document.getElementById('coinType');
    mnDictTag = document.getElementById('mnDict');
    signMessageTag = document.getElementById('signMessage');
    verifyMessageTag = document.getElementById('verifyMessage');
    verifyResultTag = document.getElementById('verifyResult');
    dataHashTag = document.getElementById('dataHash');
    keyImageTag = document.getElementById('keyImage');
    keyImageResultsTag = document.getElementById('keyImageResults');
    encKeyTag = document.getElementById('encKey');
    encMnTag = document.getElementById('encMn');
    encTypeTag = document.getElementById('encType');
    encKey2Tag = document.getElementById('encKey2');
    addrPt2Tag = document.getElementById('addrPt2');
    derivedAddrTag = document.getElementById('derivedAddr');
    mnemonicPt2Tag = document.getElementById('mnemonicPt2');
    derivedSpendKeyTag = document.getElementById('derivedSpendKey');
    derivedViewKeyTag = document.getElementById('derivedViewKey');
    if (dataHashTag !== null){
        hashUpdate(document.getElementById('theData').value);
    }//BrainWallet
    bw_phrase = document.getElementById('bw_input');
    bw_hexSeed = document.getElementById('bw_hexSeed');
    bw_privSpend = document.getElementById('bw_privSpend');
    bw_pubSpend = document.getElementById('bw_pubSpend');
    bw_privView = document.getElementById('bw_privView');
    bw_pubView = document.getElementById('bw_pubView');
    bw_pubAddr = document.getElementById('bw_pubAddr');
    bw_mnemonic = document.getElementById('bw_mnemonic');
}

//BrainWallet, blame Taushet if there is an error here, not Luigi1111
function bwGen() {
	
	//Clear
	bw_hexSeed.value = "";
    bw_privSpend.value = "";
    bw_pubSpend.value = "";
    bw_privView.value = "";
    bw_pubView.value = "";
    bw_pubAddr.value = "";
	
	//Generate Hex Seed
	var hs = keccak_256(bw_phrase.value);
	
	//Generate Keys
    var pID = "";
    var netbyte = pubAddrNetByte.value;
    if (netbyte === "11"){
        if (hs.length == 64){
            var privSk = sc_reduce32(hs);
            var privVk = sc_reduce32(cn_fast_hash(sec_key_to_pub(privSk)));
        } else {
            var privSk = sc_reduce32(cn_fast_hash(hs));
            var privVk = sc_reduce32(cn_fast_hash(sec_key_to_pub(privSk)));
        }
    } else {
        if (hs.length == 64){
            var privSk = sc_reduce32(hs);
            var privVk = sc_reduce32(cn_fast_hash(privSk));
        } else {
            var privSk = sc_reduce32(cn_fast_hash(hs));
            var privVk = sc_reduce32(cn_fast_hash(cn_fast_hash(hs)));
        }
        if (netbyte === "13"){
            pID = rand_32().slice(0,16);
        }
    }
    var pubVk = sec_key_to_pub(privVk);
    var pubSk = sec_key_to_pub(privSk);
    var address = toPublicAddr(netbyte, pubSk, pubVk, pID);
	
	//Generate MN
	bw_mnemonic.value = mn_encode(hs, mnDictTag.value)
	
	//Publish
    bw_hexSeed.value = hs;
    bw_privSpend.value = privSk;
    bw_pubSpend.value = pubSk;
    bw_privView.value = privVk;
    bw_pubView.value = pubVk;
    bw_pubAddr.value = address;
}

//RCT amount base
var H = "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94";
var l = JSBigInt("7237005577332262213973186563042994240857116359379907606001950938285454250989");
var I = "0100000000000000000000000000000000000000000000000000000000000000"; //identity element
var Z = "0000000000000000000000000000000000000000000000000000000000000000"; //zero scalar
var H2 = ["8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94",
    "8faa448ae4b3e2bb3d4d130909f55fcd79711c1c83cdbccadd42cbe1515e8712",
    "12a7d62c7791654a57f3e67694ed50b49a7d9e3fc1e4c7a0bde29d187e9cc71d",
    "789ab9934b49c4f9e6785c6d57a498b3ead443f04f13df110c5427b4f214c739",
    "771e9299d94f02ac72e38e44de568ac1dcb2edc6edb61f83ca418e1077ce3de8",
    "73b96db43039819bdaf5680e5c32d741488884d18d93866d4074a849182a8a64",
    "8d458e1c2f68ebebccd2fd5d379f5e58f8134df3e0e88cad3d46701063a8d412",
    "09551edbe494418e81284455d64b35ee8ac093068a5f161fa6637559177ef404",
    "d05a8866f4df8cee1e268b1d23a4c58c92e760309786cdac0feda1d247a9c9a7",
    "55cdaad518bd871dd1eb7bc7023e1dc0fdf3339864f88fdd2de269fe9ee1832d",
    "e7697e951a98cfd5712b84bbe5f34ed733e9473fcb68eda66e3788df1958c306",
    "f92a970bae72782989bfc83adfaa92a4f49c7e95918b3bba3cdc7fe88acc8d47",
    "1f66c2d491d75af915c8db6a6d1cb0cd4f7ddcd5e63d3ba9b83c866c39ef3a2b",
    "3eec9884b43f58e93ef8deea260004efea2a46344fc5965b1a7dd5d18997efa7",
    "b29f8f0ccb96977fe777d489d6be9e7ebc19c409b5103568f277611d7ea84894",
    "56b1f51265b9559876d58d249d0c146d69a103636699874d3f90473550fe3f2c",
    "1d7a36575e22f5d139ff9cc510fa138505576b63815a94e4b012bfd457caaada",
    "d0ac507a864ecd0593fa67be7d23134392d00e4007e2534878d9b242e10d7620",
    "f6c6840b9cf145bb2dccf86e940be0fc098e32e31099d56f7fe087bd5deb5094",
    "28831a3340070eb1db87c12e05980d5f33e9ef90f83a4817c9f4a0a33227e197",
    "87632273d629ccb7e1ed1a768fa2ebd51760f32e1c0b867a5d368d5271055c6e",
    "5c7b29424347964d04275517c5ae14b6b5ea2798b573fc94e6e44a5321600cfb",
    "e6945042d78bc2c3bd6ec58c511a9fe859c0ad63fde494f5039e0e8232612bd5",
    "36d56907e2ec745db6e54f0b2e1b2300abcb422e712da588a40d3f1ebbbe02f6",
    "34db6ee4d0608e5f783650495a3b2f5273c5134e5284e4fdf96627bb16e31e6b",
    "8e7659fb45a3787d674ae86731faa2538ec0fdf442ab26e9c791fada089467e9",
    "3006cf198b24f31bb4c7e6346000abc701e827cfbb5df52dcfa42e9ca9ff0802",
    "f5fd403cb6e8be21472e377ffd805a8c6083ea4803b8485389cc3ebc215f002a",
    "3731b260eb3f9482e45f1c3f3b9dcf834b75e6eef8c40f461ea27e8b6ed9473d",
    "9f9dab09c3f5e42855c2de971b659328a2dbc454845f396ffc053f0bb192f8c3",
    "5e055d25f85fdb98f273e4afe08464c003b70f1ef0677bb5e25706400be620a5",
    "868bcf3679cb6b500b94418c0b8925f9865530303ae4e4b262591865666a4590",
    "b3db6bd3897afbd1df3f9644ab21c8050e1f0038a52f7ca95ac0c3de7558cb7a",
    "8119b3a059ff2cac483e69bcd41d6d27149447914288bbeaee3413e6dcc6d1eb",
    "10fc58f35fc7fe7ae875524bb5850003005b7f978c0c65e2a965464b6d00819c",
    "5acd94eb3c578379c1ea58a343ec4fcff962776fe35521e475a0e06d887b2db9",
    "33daf3a214d6e0d42d2300a7b44b39290db8989b427974cd865db011055a2901",
    "cfc6572f29afd164a494e64e6f1aeb820c3e7da355144e5124a391d06e9f95ea",
    "d5312a4b0ef615a331f6352c2ed21dac9e7c36398b939aec901c257f6cbc9e8e",
    "551d67fefc7b5b9f9fdbf6af57c96c8a74d7e45a002078a7b5ba45c6fde93e33",
    "d50ac7bd5ca593c656928f38428017fc7ba502854c43d8414950e96ecb405dc3",
    "0773e18ea1be44fe1a97e239573cfae3e4e95ef9aa9faabeac1274d3ad261604",
    "e9af0e7ca89330d2b8615d1b4137ca617e21297f2f0ded8e31b7d2ead8714660",
    "7b124583097f1029a0c74191fe7378c9105acc706695ed1493bb76034226a57b",
    "ec40057b995476650b3db98e9db75738a8cd2f94d863b906150c56aac19caa6b",
    "01d9ff729efd39d83784c0fe59c4ae81a67034cb53c943fb818b9d8ae7fc33e5",
    "00dfb3c696328c76424519a7befe8e0f6c76f947b52767916d24823f735baf2e",
    "461b799b4d9ceea8d580dcb76d11150d535e1639d16003c3fb7e9d1fd13083a8",
    "ee03039479e5228fdc551cbde7079d3412ea186a517ccc63e46e9fcce4fe3a6c",
    "a8cfb543524e7f02b9f045acd543c21c373b4c9b98ac20cec417a6ddb5744e94",
    "932b794bf89c6edaf5d0650c7c4bad9242b25626e37ead5aa75ec8c64e09dd4f",
    "16b10c779ce5cfef59c7710d2e68441ea6facb68e9b5f7d533ae0bb78e28bf57",
    "0f77c76743e7396f9910139f4937d837ae54e21038ac5c0b3fd6ef171a28a7e4",
    "d7e574b7b952f293e80dde905eb509373f3f6cd109a02208b3c1e924080a20ca",
    "45666f8c381e3da675563ff8ba23f83bfac30c34abdde6e5c0975ef9fd700cb9",
    "b24612e454607eb1aba447f816d1a4551ef95fa7247fb7c1f503020a7177f0dd",
    "7e208861856da42c8bb46a7567f8121362d9fb2496f131a4aa9017cf366cdfce",
    "5b646bff6ad1100165037a055601ea02358c0f41050f9dfe3c95dccbd3087be0",
    "746d1dccfed2f0ff1e13c51e2d50d5324375fbd5bf7ca82a8931828d801d43ab",
    "cb98110d4a6bb97d22feadbc6c0d8930c5f8fc508b2fc5b35328d26b88db19ae",
    "60b626a033b55f27d7676c4095eababc7a2c7ede2624b472e97f64f96b8cfc0e",
    "e5b52bc927468df71893eb8197ef820cf76cb0aaf6e8e4fe93ad62d803983104",
    "056541ae5da9961be2b0a5e895e5c5ba153cbb62dd561a427bad0ffd41923199",
    "f8fef05a3fa5c9f3eba41638b247b711a99f960fe73aa2f90136aeb20329b888"];

//conversion functions, etc
function coinType(type){
    pubAddrNetByte.value = type;
    if (payIdWrap !== null){
        if (type === "13"){
            payIdWrap.style.display = "";
        } else {
            payIdWrap.style.display = "none";
        }
    }
    if (type === "11" || type === "12" || type === "13" || type === "35"){
        mnDictTag.value = "english";
    } else if (type === "b201" || type === "01"){
        mnDictTag.value = "electrum";
    }
}

function validHex(hex){
    var exp = new RegExp("[0-9a-fA-F]{" + hex.length + "}");
    return exp.test(hex);
}

function hextobin(hex){
    if (hex.length % 2 !== 0) throw "Hex string has invalid length!";
        var res = new Uint8Array(hex.length / 2);
    for (var i = 0; i < hex.length / 2; ++i) {
        res[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return res;
}

function bintohex(bin){
    var out = [];
    for (var i = 0; i < bin.length; ++i) {
        out.push(("0" + bin[i].toString(16)).slice(-2));
    }
    return out.join("");
}

function cn_faster_hash(hex){
    return keccak_256(hextobin(hex));
}

function hexXor(hex1, hex2){
    if (!hex1 || !hex2 || hex1.length !== hex2.length || hex1.length % 2 !== 0 || hex2.length % 2 !== 0){throw "bad input";}
    var bin1 = hextobin(hex1);
    var bin2 = hextobin(hex2);
    var xor = new Uint8Array(bin1.length);
    for (var i = 0; i < xor.length; i++){
        xor[i] = bin1[i] ^ bin2[i];
    }
    return bintohex(xor);
}

//decode amount and mask and check against commitment
function decodeRct(rv, i, der){
    var key = derivation_to_scalar(der, i);
    var ecdh = decode_rct_ecdh(rv.ecdhInfo[i], key);
    //console.log("ecdh: " + ecdh);
    var Ctmp = commit(ecdh.amount, ecdh.mask);
    //console.log("C: " + Ctmp);
    if (Ctmp !== rv.outPk[i]){
        throw "mismatched commitments!";
    }
    ecdh.amount = s2d(ecdh.amount);
    return ecdh;
}

//rct functions as I need them

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
    for (var i = 1; i <= hex.length / 2; i++){
        data += hex.substr(0 - 2 * i, 2);
    }
    return data;
}

//switch byte order charwise
function swapEndianC(string){
    var data = "";
    for (var i = 1; i <= string.length; i++){
        data += string.substr(0 - i, 1);
    }
    return data;
}

//for most uses you'll also want to swapEndian after conversion
//mainly to convert integer "scalars" to usable hexadecimal strings
function d2h256(integer){
    if (typeof integer !== "string" && integer.toString().length > 15){throw "integer should be entered as a string for precision";}
    var padding = "";
    for (var i = 0; i < 63; i++){
        padding += "0";
    }
    return (padding + JSBigInt(integer).toString(16).toLowerCase()).slice(-64);
}

function d2h(integer){
    return d2h256(integer);
}

//integer to scalar
function d2s(integer){
    return swapEndian(d2h(integer));
}

function s2d(scalar){
    return JSBigInt.parse(swapEndian(scalar), 16).toString();
}

//integer to mantissa+exp
function d2m(integer){
    if (typeof integer !== "string" && integer.toString().length > 15){throw "integer should be entered as a string for precision";}
    integer = integer.toString();
    var d = "0";
    var i = 0;
    while (d === "0"){
        i++;
        d = integer.substr(-i, 1);
    }
    i--;
    var res = {
        m: integer.slice(0, -i),
        e: i
    };
    return res;
}

//convert integer string to 64bit "binary" little-endian string
function d2b(integer){
    if (typeof integer !== "string" && integer.toString().length > 15){throw "integer should be entered as a string for precision";}
    var padding = "";
    for (var i = 0; i < 63; i++){
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
    for (var i = 0; i < 31; i++){
        padding += "0";
    }
    var a = new JSBigInt(integer);
    if (a.toString(2).length > 64){throw "amount overflows uint64!";}
    return swapEndianC((padding + a.toString(4)).slice(-32));
}

//-------------------------------------------------------------------------------------------

//addressestests/gen.html functions
function allRandom(){
    var netbyte = pubAddrNetByte.value;
    if (netbyte === "11"){
        var hs = sc_reduce32(rand_32());
        var mn = mn_encode(hs, mnDictTag.value);
        var privSk = hs;
        var pubSk = sec_key_to_pub(privSk);
        var privVk = sc_reduce32(cn_fast_hash(pubSk));
        var pubVk = sec_key_to_pub(privVk);
    } else {
        var hs = sc_reduce32(rand_32());
        var mn = mn_encode(hs, mnDictTag.value);
        var privSk = hs;
        var privVk = sc_reduce32(cn_fast_hash(hs));
        var pubSk = sec_key_to_pub(privSk);
        var pubVk = sec_key_to_pub(privVk);
        if (netbyte === "13"){
            var pID = rand_32().slice(0,16);
        }
    }
    var address = toPublicAddr(netbyte, pubSk, pubVk, pID);
    if (!pID){
        paymentID.value = "";
    } else {
        paymentID.value = pID;
    }
    mnemonic.value = mn;
    hexSeed.value = hs;
    privSpend.value = privSk;
    pubSpend.value = pubSk;
    privView.value = privVk;
    pubView.value = pubVk;
    pubAddr.value = address;
}

function allRandomMm(){
    var netbyte = pubAddrNetByte.value;
    var hs = rand_16();
    var hs32 = cn_fast_hash(hs);
    var i = 0;
    while (hs32 !== sc_reduce32(hs32)){
        hs = rand_16();
        hs32 = cn_fast_hash(hs);
        i++
    }
    console.log("Found simplewallet-compatible MyMonero seed after " + i + " attempts (~16 expected).");
    if (netbyte === "11"){
        //var hs = rand_16();
        var mn = mn_encode(hs, mnDictTag.value);
        var privSk = sc_reduce32(hs32);
        var pubSk = sec_key_to_pub(privSk);
        var privVk = sc_reduce32(cn_fast_hash(pubSk));
        var pubVk = sec_key_to_pub(privVk);
    } else {
        //var hs = rand_16();
        var mn = mn_encode(hs, mnDictTag.value);
        var privSk = sc_reduce32(hs32);
        var privVk = sc_reduce32(cn_fast_hash(hs32));
        var pubSk = sec_key_to_pub(privSk);
        var pubVk = sec_key_to_pub(privVk);
        if (netbyte === "13"){
            var pID = rand_32().slice(0,16);
        }
    }
    var address = toPublicAddr(netbyte, pubSk, pubVk, pID);
    if (!pID){
        paymentID.value = "";
    } else {
        paymentID.value = pID;
    }
    mnemonic.value = mn;
    hexSeed.value = hs;
    privSpend.value = privSk;
    pubSpend.value = pubSk;
    privView.value = privVk;
    pubView.value = pubVk;
    pubAddr.value = address;
}

function addressGen(){
    hexSeed.value = "";
    privSpend.value = "";
    pubSpend.value = "";
    privView.value = "";
    pubView.value = "";
    pubAddr.value = "";
    var mn = mnemonic.value;
    if (mn === ""){
        mnemonic.value = "Missing seed! Please enter it and try again.";
        return;
    }
    try{
        var hs = mn_decode(mn, mnDictTag.value);
    }
    catch(err){
        pubAddr.value = err;
        return;
    }
    if (hs.length !== 32 && hs.length !== 64){
        pubAddr.value = "invalid seed length!";
        return;
    }
    var pID = "";
    var netbyte = pubAddrNetByte.value;
    if (netbyte === "11"){
        if (hs.length == 64){
            var privSk = sc_reduce32(hs);
            var privVk = sc_reduce32(cn_fast_hash(sec_key_to_pub(privSk)));
        } else {
            var privSk = sc_reduce32(cn_fast_hash(hs));
            var privVk = sc_reduce32(cn_fast_hash(sec_key_to_pub(privSk)));
        }
    } else {
        if (hs.length == 64){
            var privSk = sc_reduce32(hs);
            var privVk = sc_reduce32(cn_fast_hash(privSk));
        } else {
            var privSk = sc_reduce32(cn_fast_hash(hs));
            var privVk = sc_reduce32(cn_fast_hash(cn_fast_hash(hs)));
        }
        if (netbyte === "13"){
            pID = rand_32().slice(0,16);
        }
    }
    var pubVk = sec_key_to_pub(privVk);
    var pubSk = sec_key_to_pub(privSk);
    var address = toPublicAddr(netbyte, pubSk, pubVk, pID);
    if (pID){
        paymentID.value = pID;
    }
    hexSeed.value = hs;
    privSpend.value = privSk;
    pubSpend.value = pubSk;
    privView.value = privVk;
    pubView.value = pubVk;
    pubAddr.value = address;
}

function encryptMnOld(encrypt){
    var mn = (encrypt) ? mn_decode(mnemonic.value, mnDictTag.value) : mn_decode(encMnTag.value, mnDictTag.value);
    var pass = encKeyTag.value;
    var key = keccak_256(pass); //"cn_fast_hash" but with text input
    for (var i = 0; i < 10000; i++){
        key = cn_fast_hash(key); //takes output of above as hex, rather than text
    }
    if (mn.length === 64){
        var mnResult = mn_encode(hex_xor(mn, key), mnDictTag.value);
    } else {
        var mnResult = mn_encode(hex_xor(mn, key.slice(0,32)), mnDictTag.value);
    }
    if (encrypt){
        encMnTag.value = mnResult;
    } else {
        mnemonic.value = mnResult;
    }
}

function encryptMnXor(encrypt){
    var mn = (encrypt) ? mn_decode(mnemonic.value, mnDictTag.value) : mn_decode(encMnTag.value, mnDictTag.value);
    var pass = encKeyTag.value;
    setTimeout(function (encrypt, mn, pass){
        var d = new Date().getTime(); 
        var key = bintohex(SlowHash.string(pass));
        var t = new Date().getTime() - d;
        console.log("cn_slow_hash time: " + t);
        var mnResult = mn_encode(hex_xor(mn, key.slice(0, mn.length)), mnDictTag.value);
        if (encrypt){
            encMnTag.value = mnResult;
        } else {
            mnemonic.value = mnResult;
        }
    }, 50, encrypt, mn, pass);
}

function encryptMnAdd(encrypt){
    var mn = (encrypt) ? mn_decode(mnemonic.value, mnDictTag.value) : mn_decode(encMnTag.value, mnDictTag.value);
    var pass = encKeyTag.value;
    if (mn.length !== 64){
        if (encrypt){
            encMnTag.value = "This method only works with 25 word seeds!";
        } else {
            mnemonic.value = "This method only works with 25 word seeds!";
        }
        return;
    }
    setTimeout(function (encrypt, mn, pass){
        var d = new Date().getTime(); 
        var key = sc_reduce32(bintohex(SlowHash.string(pass)));
        var t = new Date().getTime() - d;
        console.log("cn_slow_hash time: " + t);
        var mnResult = (encrypt) ? mn_encode(sc_add(mn, key), mnDictTag.value) : mn_encode(sc_sub(mn, key), mnDictTag.value);
        if (encrypt){
            encMnTag.value = mnResult;
        } else {
            mnemonic.value = mnResult;
        }
    }, 50, encrypt, mn, pass);
}

function encryptMnWrap(encrypt){
    if (encrypt){
        encMnTag.value = "Encrypting...";
    } else {
        mnemonic.value = "Decrypting...";
    }
    if (encTypeTag.value === "keccak"){
        encryptMnOld(encrypt);
    } else if (encTypeTag.value === "cnxor"){
        encryptMnXor(encrypt);
    } else if (encTypeTag.value === "cnadd"){
        var mn = (encrypt) ? mn_decode(mnemonic.value, mnDictTag.value) : mn_decode(encMnTag.value, mnDictTag.value);
        if (mn.length !== 64){
            encTypeTag.value = "cnxor";
            if (encrypt){
                encMnTag.value = "You can chosen CN Add with a MyMonero seed. Switching to CN XOR and encrypting...";
            } else {
                mnemonic.value = "You can chosen CN Add with a MyMonero seed. Switching to CN XOR and decrypting...";
            }
            encryptMnXor(encrypt);
            return;
        }
        encryptMnAdd(encrypt);
    }
}


//new address = B+C, A, where C is a derived pubkey from the 2fa key
function deriveAddr(){
    derivedAddrTag.value = "";
    if (addrPt2Tag.value === ""){
        return;
    }
    try{
        var keys = decode_address(addrPt2Tag.value);
        if (cnBase58.decode(addrPt2Tag.value).slice(0, pubAddrNetByte.value.length) !== pubAddrNetByte.value){
            throw "Make sure you have selected the right network byte for your intended address type!";
        }
    } catch (err){
        derivedAddrTag.value = err;
        return;
    }
    var pass = encKey2Tag.value;
    derivedAddrTag.value = "Calculating...";
    setTimeout(function (keys, pass){
        var d = new Date().getTime(); 
        var scalar = sc_reduce32(bintohex(SlowHash.string(pass)));
        var t = new Date().getTime() - d;
        console.log("cn_slow_hash time: " + t);
        var pub2 = sec_key_to_pub(scalar);
        var derivedPub = ge_add(keys.spend, pub2);
        try{
            derivedAddrTag.value = toPublicAddr(pubAddrNetByte.value, derivedPub, keys.view, (keys.intPaymentId === undefined) ? "": keys.intPaymentId);
        } catch (err){
            derivedAddrTag.value = err;
        }
    }, 50, keys, pass);
}

//new private keys = b+c, a, where c is a derived scalar from the 2fa key
function derive2faKeys(){
    derivedSpendKeyTag.value = "";
    derivedViewKeyTag.value = "";
    if (mnemonicPt2Tag.value === ""){
        return;
    }
    try{
        var scalar1 = sc_reduce32(mn_decode(mnemonicPt2Tag.value)); //ensure seed is reduced
    } catch (err){
        derivedSpendKeyTag.value = err;
        return;
    }
    var pass = encKey2Tag.value;
    derivedAddrTag.value = "Calculating...";
    setTimeout(function (scalar1, pass){
        var d = new Date().getTime(); 
        var scalar2 = sc_reduce32(bintohex(SlowHash.string(pass)));
        var t = new Date().getTime() - d;
        console.log("cn_slow_hash time: " + t);
        var spendKey = sc_add(scalar1, scalar2);
        var viewKey = sc_reduce32(cn_fast_hash(scalar1));
        try{
            derivedAddrTag.value = toPublicAddr(pubAddrNetByte.value, sec_key_to_pub(spendKey), sec_key_to_pub(viewKey), paymentID.value); //be careful with the selected netbyte here (at top left of page)!
        } catch (err){
            derivedAddrTag.value = err;
        }
        derivedSpendKeyTag.value = spendKey;
        derivedViewKeyTag.value = viewKey;
    }, 50, scalar1, pass);
}

function mnemonicRandom(){
    mnemonic.value = mn_encode(sc_reduce32(rand_32()), mnDictTag.value);
}

function mnemonicSubmit(){
    hexSeed.value = mn_decode(mnemonic.value, mnDictTag.value);
}

function hexSeedSubmit(){
    var hs = hexSeed.value;
    if (hs.length != 64) {
        hs = cn_fast_hash(hs);
        var spend = sc_reduce32(hs);
        privSpend.value = spend;
        var view = sc_reduce32(cn_fast_hash(hs));
        privView.value = view;
    } else {
        var spend = sc_reduce32(hs);
        privSpend.value = spend;
        var view = sc_reduce32(cn_fast_hash(spend));
        privView.value = view;
    }
}

function hexSeedRandom(){
	hexSeed.value = sc_reduce32(rand_32());
}

function hexSeedToMn(){
    mnemonic.value = mn_encode(hexSeed.value, mnDictTag.value);
}

function spendSubmit(){
    pubSpend.value =  sec_key_to_pub(privSpend.value);
}

function spendRandom(){
    privSpend.value = sc_reduce32(rand_32());
}

function pubToView(){
    privView.value = sc_reduce32(cn_fast_hash(pubSpend.value));
}

function viewSubmit(){
    pubView.value = sec_key_to_pub(privView.value);
}

function viewRandom(){
    privView.value = sc_reduce32(rand_32());
}

function randID(){
    paymentID.value = mn_random(64);
}
	
function addrSubmit(){
    var netbyte = pubAddrNetByte.value;
    var pubsk = pubSpend.value;
    var pubvk = pubView.value;
    var pid = paymentID.value;
    if (pubsk.length !== 64 || (netbyte !== "11" && pubvk.length !== 64)){
        pubAddr.value = "Invalid Length on pubSpendKey or pubViewKey!";
        throw "Invalid length!";
    }
    if (pid !== "" && netbyte !== "13"){
        pubAddr.value = "This address type (" + netbyte + ") should not have a payment ID!";
        throw "pID where none expected"
    }
    if (netbyte === "13" && pid.length !== 16){
        pubAddr.value = "This address type (" + netbyte + ") needs a payment ID of 16 hex digits!";
        throw "Bad pID for integrated address!";
    }
    pubAddr.value = toPublicAddr(netbyte, pubsk, pubvk, pid);
}

function toPublicAddr(netbyte, pubsk, pubvk, pid){
    if (pubvk === undefined){pubk = "";}
    if (pid === undefined){pid = "";}
    if ((netbyte !== "13" && pid !== "") || (netbyte === "13" && pid === "")){throw "pid or no pid with wrong address type";}
    if (netbyte === "11"){pubvk = "";}
    var preAddr = netbyte + pubsk + pubvk + pid;
    var hash = cn_fast_hash(preAddr);
    var addrHex = preAddr + hash.slice(0,8);
    return cnBase58.encode(addrHex);
}

function toAddrTest(){
    pubAddr2.value = pubAddr.value;
}

function addrCheck(){
    clearAddr();
    var addr58 = pubAddr2.value;
    if (addr58.length !== 95 && addr58.length !== 97 && addr58.length !== 51 && addr58.length !== 106){
        validNo.innerHTML = "Invalid Address Length: " + addr58.length;
        throw "Invalid Address Length!";
    }
    var addrHex = cnBase58.decode(addr58);
    if (addrHex.length === 140){
        var netbyte = addrHex.slice(0,4);
    } else {
        var netbyte = addrHex.slice(0,2);
    }
    coins = {};
    for (var i = 0; i < coinTypeTag.getElementsByTagName('option').length; i++){
        coins[coinTypeTag.getElementsByTagName('option')[i].value] = coinTypeTag.getElementsByTagName('option')[i].innerHTML;
    }
    //viewkey + pID stuff
    if (netbyte === "13"){
        if (addrHex.length !== 154){
            validNo.innerHTML = "Invalid Address Length: " + addr58.length + " for " + coins[netbyte];
            throw "Invalid Address Length";
        }
        extraInput.value = addrHex.slice(130,-8);
    }
    if (netbyte === "11"){
        if (addrHex.length !== 74){
            clearAddr();
            validNo.innerHTML = "Invalid Address Length: " + addr58.length + " for " + coins[netbyte];
            throw "Invalid Address Length";
        }
        var privVk = sc_reduce32(cn_fast_hash(addrHex.slice(2,66)));
        extraInput.value = privVk;
        pubView2.value = sec_key_to_pub(privVk);
    } else if (addrHex.length === 140){
        pubView2.value = addrHex.slice(68,132);
    } else {
        pubView2.value = addrHex.slice(66,130);
    }
    if ((netbyte !== "11" && netbyte !== "13") && addrHex.length !== 138 && addrHex.length !== 140){
        clearAddr();
        validNo.innerHTML = "Invalid Address Length: " + addr58.length + " for " + coins[netbyte];
        throw "Invalid Address Length!";
    }
    var addrHash = cn_fast_hash(addrHex.slice(0,-8));
    pubAddrHex.value = addrHex;
    if (addrHex.length === 140){
        pubSpend2.value = addrHex.slice(4,68);
    } else {
        pubSpend2.value = addrHex.slice(2,66);
    }
    pubAddrChksum.value = addrHex.slice(-8);
    pubAddrForHash.value = addrHex.slice(0,-8);
    pubAddrHash.value = addrHash;
    pubAddrChksum2.value = addrHash.slice(0,8);
    if (addrHex.slice(-8) == addrHash.slice(0,8)) {
        validYes.innerHTML = "Yes! This is a valid " + coins[netbyte] + " address.";
    } else {
        validNo.innerHTML = "No! Checksum invalid!";
        validYes.innerHTML = "";
    }
    xmrAddr.value = toPublicAddr("12", pubSpend2.value, pubView2.value);
}
    
function clearAddr(){
    pubAddrHex.value = "";
    extraInput.value = "";
    pubSpend2.value = "";
    pubView2.value = "";
    pubAddrChksum.value = "";
    pubAddrForHash.value = "";
    pubAddrHash.value = "";
    pubAddrChksum2.value = "";
    validYes.innerHTML = "";
    validNo.innerHTML = "";
    xmrAddr.value = "";
}


//for checktx.html -- need to add support for multiple tx pubkeys at some point...
function parseExtra(bin){
    var extra = {
        pub: false,
        paymentId: false
    };
    if (bin[0] === 1){ //pubkey is tag 1
        extra.pub = bintohex(bin.slice(1, 33)); //pubkey is 32 bytes
        if (bin[33] === 2 && bin[35] === 0 || bin[35] === 1){
            extra.paymentId = bintohex(bin.slice(36, 36 + bin[34] - 1));
        }
    } else if (bin[0] === 2){
        if (bin[2] === 0 || bin[2] === 1){
            extra.paymentId = bintohex(bin.slice(3, 3 + bin[1] - 1));
        }
        //second byte of nonce is nonce payload length; payload length + nonce tag byte + payload length byte should be the location of the pubkey tag
        if (bin[2 + bin[1]] === 1){
            var offset = 2 + bin[1];
            extra.pub = bintohex(bin.slice(offset + 1, offset + 1 + 32));
        }
    }
    return extra;
}

function checkTx(isFundingTx){
    resultsTag.innerHTML = "";
    var err = 0;
    var sec = private.value;
    if (sec.length !== 64 || validHex(sec) !== true){
        resultsTag.innerHTML += "<span class='validNo'>Your private key is invalid. Please check it and try again.</span><br>"
        err = 1;
    }
    var addr = addrTag.value;
    if (addr == ""){
    	resultsTag.innerHTML += "<span class='validNo'>Address is required. Please enter your/the recipient's address and try again.</span><br>";
        err = 2;
    }
    if (err !== 2 && addr.length !== 95 && addr.length !== 104){
    	resultsTag.innerHTML += "<span class='validNo'>Your address is the wrong length! Please check it and try again.</span><br>";
        err = 2;
    } else {
        var addrHex = cnBase58.decode(addr);
        if (err !== 2 && addrHex.slice(-8) !== cn_fast_hash(addrHex.slice(0,-8)).slice(0,8)){ //checksum validation
            resultsTag.innerHTML += "<span class='validNo'>Address validation failed! Please check it and try again.</span><br>";
            err = 2;
        }
    }
    if (err === 0 && typeTag.value === "Private Viewkey"){
        if (addrHex.slice(66,130) !== sec_key_to_pub(sec) && !is_subaddress(addr)){
            resultsTag.innerHTML += "<span class='validNo'>Your View Key doesn't match your address. Please check it and try again.</span><br>"
            err = 1;
        }
    }
    var hash = txHash.value;
    if (hash.length !== 64 || !validHex(hash)){
        resultsTag.innerHTML += "<span class='validNo'>Your transaction hash is missing or invalid. Please check it and try again.</span><br>";
        err = 3;
    }
    if (err !== 0){throw "One or more things are wrong with your inputs!";}
    var spk = addrHex.slice(2,66);
    var fullapi = api + "get_transaction_data/";
    var res = $.ajax({url: fullapi + hash, type: 'GET', async: false});
    if (res.statusText !== "OK"){
    	resultsTag.innerHTML = "<span class='validNo'>Failed to get transaction data! Perhaps MoneroBlocks is down?</span>";
        throw "Failed to get transaction data!";
    }
    res = JSON.parse(res.responseText);
    if (res.status !== "OK"){
    	resultsTag.innerHTML = "<span class='validNo'>Failed to get transaction data! Your Tx Hash probably doesn't exist.</span>";
        throw "Failed to get transaction data!";
    }
    if (res.transaction_data === null){
    	resultsTag.innerHTML = "<span class='validNo'>Your transaction exists, but we failed to get its data! MoneroBlocks API probably has not parsed it yet.</span>";
        throw "Failed to get transaction data!";
    }

    console.log(res);
    if (typeTag.value === "Private Viewkey"){
        var extra = parseExtra(res.transaction_data.extra); //need to add support for multiple txpubkeys due to subaddresses...
        var pub = extra.pub;
        if (!pub){
            resultsTag.innerHTML = "<span class='validNo'>Unrecognized tx_extra format! Please let luigi1111 know what tx hash you were using.</span>"
            throw "Unrecognized extra format"; //definitely doesn't cover all possible extra formats, but others are quite uncommon
        }
    } else {
        var pub = addrHex.slice(66,130);
    }
    var outputNum = res.transaction_data.vout.length;
    var der = generate_key_derivation(pub, sec);
    var tot = 0;
    for (var i = 0; i < outputNum; i++){
        var pubkey = derive_public_key(der, i, spk);
        var rct = res.transaction_data.version === 2 && res.transaction_data.vout[i].amount === 0;
        if (pubkey === res.transaction_data.vout[i].target.key){
            if (rct) {
                try {
                    var ecdh = decodeRct(res.transaction_data.rct_signatures, i, der);
                } catch (err) {
                    resultsTag.innerHTML += "<span class='validNo'>RingCT amount for output " + i + " with pubkey: " + res.transaction_data.vout[i].target.key + " decoded incorrectly! It will not be spendable." + "</span>" + "<br>"; //rct commitment != computed
                    throw "invalid rct amount";
                }
                res.transaction_data.vout[i].amount = ecdh.amount;
            }
            tot += res.transaction_data.vout[i].amount;
            console.log("You own output " + i + " with pubkey: " + pubkey + " for amount: " + res.transaction_data.vout[i].amount / 1000000000000);
            resultsTag.innerHTML += "<span class='validYes'>This address owns output&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + i + " with pubkey: " + pubkey + " for amount: " + res.transaction_data.vout[i].amount / 1000000000000 + "</span>" + "<br>"; //amount / 10^12
        } else {
            console.log("You don't own output " + i + " with pubkey: " + res.transaction_data.vout[i].target.key + " for amount: " + res.transaction_data.vout[i].amount / 1000000000000);
            var resultTemp = "<span class='validNo'>This address doesn't own output " + i + " with pubkey: " + res.transaction_data.vout[i].target.key + " for amount: ";
            resultTemp += rct ? "Confidential" : res.transaction_data.vout[i].amount / 1000000000000;
            resultTemp += "</span>" + "<br>";
            resultsTag.innerHTML += resultTemp; //workaround for tags closing themselves
        }
    }
    resultsTag.innerHTML += "<br>" + "Total received: " + tot / 1000000000000; //10^12
    if (!isFundingTx && extra.paymentId && tot){
        if (extra.paymentId.length === 16){
            var decryptedId = hex_xor(extra.paymentId, cn_fast_hash(der + "8d").slice(0,16));
        } else {
            var decryptedId = extra.paymentId;
        }
        resultsTag.innerHTML += "<br>" + "Found payment ID: " + decryptedId;
    }
    if (isFundingTx && extra.paymentId !== false){
        resultsTag.innerHTML += "<br>" + "Payment ID found: " + extra.paymentId + " Matches computed hash?: " + (extra.paymentId === dataHashTag.value);
    } else if (isFundingTx){
        resultsTag.innerHTML += "<br>" + "Payment ID not found! Funding data not logged in blockchain!";
    }
    console.log("End of TX...");
}

//sign/verify functions
/*form of message:
L1: "-----BEGIN MONERO SIGNED MESSAGE-----"
L2: <message>
L3: "Address: "<address>
L4: "-----BEGIN SIGNATURE-----"
L5: <signature>
L6: "-----END MONERO SIGNED MESSAGE-----"
*/
//<signature is cnBase58 encoded, with preceding unencoded "SigV1"
function signMsg(){
    var msg = signMessage.value;
    var sec = private.value;
    var address = addr.value;
    var type = typeTag.value;
    verifyResultTag.innerHTML = "";
    if (!msg || !sec || !address){
        verifyResultTag.innerHTML = "<span class='validNo'>You are missing a required parameter! Please try again.</span>";
        return;
    }
    if (!validHex(sec) || sec.length !== 64){
        verifyResultTag.innerHTML = "<span class='validNo'>Your secret key is invalid!</span>";
        return;
    }
    if (address.length !== 95 && address.length !== 106){
        verifyResultTag.innerHTML = "<span class='validNo'>Your address is invalid length!</span>";
        return;
    }
    var addrHex = cnBase58.decode(address);
    if (addrHex.slice(-8) !== cn_fast_hash(addrHex.slice(0,-8)).slice(0,8)){ //checksum validation
        verifyResultTag.innerHTML += "<span class='validNo'>Address validation failed! Please check it and try again.</span>";
        return;
    }
    if (type === "Private Spendkey"){
        var pub = addrHex.slice(2,66);
        if (sec_key_to_pub(sec) !== pub){
            verifyResultTag.innerHTML += "<span class='validNo'>Your Private Spendkey does not belong to this address!</span>";
            return;
        }
    } else {
        var pub = addrHex.slice(66,130);
        if (sec_key_to_pub(sec) !== pub){
            verifyResultTag.innerHTML += "<span class='validNo'>Your Private Viewkey does not belong to this address!</span>";
            return;
        }
    }
    var msgHash = keccak_256(msg);
    var sig = generate_signature(msgHash, pub, sec);
    var header = "SigV1";
    sig = header + cnBase58.encode(sig);
    verifyMessage.value = "-----BEGIN MONERO SIGNED MESSAGE-----" + "\n" + msg + "\n" + "-----BEGIN SIGNATURE-----" + "\n" + address + "\n" + sig + "\n" + "-----END MONERO SIGNED MESSAGE-----";
    return;
}

function verifyMsg(){
    verifyResultTag.innerHTML = "Checking...";
    setTimeout(function(){
        var message = verifyMessage.value;
        message = message.split("\n");
        if (message.length === 6 && message[0] === "-----BEGIN MONERO SIGNED MESSAGE-----"){
            if (message[2].slice(0,8) === "Address:"){
                var address = message[2].slice(8,9) === " " ? message[2].slice(9) : message[2].slice(8);
            } else if ((message[2].length === 95 || message[2].length === 106) && message[2].slice(0,1) === "4"){
                var address = message[2];
            } else if (message[3].length === 95 || message[3].length === 106){
                var address = message[3];
            } else {
                verifyResultTag.innerHTML = "<span class='validNo'>Your address could not be parsed!</span>";
                return;
            }
            var hash = keccak_256(message[1]);
            var sig = message[4];
        } else if (message.length === 1 || (message.length === 2 && message[1] === "")){
            var sig = message[0];
            var address = addr.value;
            var msg = signMessage.value;
            if (!sig || !address){
                verifyResultTag.innerHTML = "<span class='validNo'>You are missing a required parameter! Please try again.</span>";
                return;
            }
            var hash = keccak_256(msg);
        } else {
            verifyResultTag.innerHTML = "<span class='validNo'>Could not parse signed message. Please verify it is valid.</span>";
            return;
        }
        if (!validHex(sig)){
            var header = "SigV1";
            try{
                if (sig.slice(0,5) !== header){
                    throw "bad prefix";
                }
                sig = cnBase58.decode(sig.slice(5));
            }
            catch(err){
                verifyResultTag.innerHTML = "<span class='validNo'>Could not parse message signature. Error:" + err + "</span>";
                return;
            }
        }
        var spendkey = cnBase58.decode(address).slice(2,66);
        var viewkey = cnBase58.decode(address).slice(66,130);
        try{
            var spendkeyResult = check_signature(hash, spendkey, sig);
        }
        catch(err){
            verifyResultTag.innerHTML = "<span class='validNo'>" + err + "</span>";
            return;
        }
        var viewkeyResult = false;
        if (spendkeyResult){
            verifyResultTag.innerHTML = "<span class='validYes'>This signature is valid for this address's spend key.</span>";
        } else {
            try{
                viewkeyResult = check_signature(hash, viewkey, sig);
            }
            catch(err){
                verifyResultTag.innerHTML = "<span class='validNo'>" + err + "</span>";
                return;
            }
            if (viewkeyResult){
                verifyResultTag.innerHTML = "<span class='validYes'>This signature is valid for this address's view key.</span>";
            } else {
                verifyResultTag.innerHTML = "<span class='validNo'>This signature is not valid for this address.</span>";
            }
        }
    }, 25);
}

//functions for coin pages
function hashUpdate(data){
    dataHashTag.value = keccak_256(data);
}

function queryKeyImage(){
    var ki = keyImageTag.value;
    var fullapi = api + "is_key_image_spent/"
    var res = $.ajax({url: fullapi + ki, type: 'GET', async: false});
    if (res.statusText !== "OK"){
    	keyImageResultsTag.innerHTML = "<span class='validNo'>Failed to get key image data! Perhaps MoneroBlocks is down?</span>";
        return;
    }
    res = JSON.parse(res.responseText);
    if (res.status !== "OK"){
    	keyImageResultsTag.innerHTML = "<span class='validNo'>ResponseText status != OK</span>";
        return;
    }
    if (res.spent_status[0] === 0){
        keyImageResultsTag.innerHTML = "<span class='validYes'>Output is unspent.</span>";
    } else if (res.spent_status[0] === 1){
        keyImageResultsTag.innerHTML = "<span class='validNo'>Key image is spent and coin has no value!</span>";
    }
}

//other functions
function genQR(){
    var payload = pubAddr.value;
    var data = "oa1:xmr recipient_address=" + payload + ";";
    var type;
    if (data.length <= 14){
        type = 1;
    } else if (data.length <= 26){
        type = 2;
    } else if (data.length <= 42){
        type = 3;
    } else if (data.length <= 62){
        type = 4;
    } else if (data.length <= 84){
        type = 5;
    } else if (data.length <= 106){
        type = 6;
    } else if (data.length <= 122){
        type = 7;
    } else if (data.length <= 152){
        type = 8;
    } else if (data.length <= 180){
        type = 9;
    } else if (data.length <= 214){
        type = 10;
    } else {
    	throw "Too many characters!";
    }
    var qr = qrcode(type, 'M');
    qr.addData(data);
    qr.make();
    qrTag.innerHTML = qr.createImgTag();
}

function cryptonightWorker(){
    var data = document.getElementById('slowHashInp').value;
    if (data.length % 2 !== 0 || validHex(data) !== true){
        document.getElementById('slowHashOut').value = "Bad input!";
        return "Bad input!";
    }
    document.getElementById('slowHashOut').value = "Calculating...";
    setTimeout(function (data){
        var d = new Date().getTime();
        var result = bintohex(SlowHash.hex(data));
        var t = new Date().getTime() - d;
        console.log("cn_slow_hash time: " + t);
        document.getElementById('slowHashOut').value = result;
    }, 50, data);
}
