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
derivedSpendKeyTag, derivedViewKeyTag;

var api = "http://moneroblocks.info/api/";

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
    encKey2Tag = document.getElementById('encKey2');
    addrPt2Tag = document.getElementById('addrPt2');
    derivedAddrTag = document.getElementById('derivedAddr');
    mnemonicPt2Tag = document.getElementById('mnemonicPt2');
    derivedSpendKeyTag = document.getElementById('derivedSpendKey');
    derivedViewKeyTag = document.getElementById('derivedViewKey');
    if (dataHashTag !== null){
        hashUpdate(document.getElementById('theData').value);
    }
}


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
    if (!hex1 || !hex2 || hex1.length !== hex2.length || hex1.length % 2 !== 0 || hex2.length % 2 !== 0){return false;}
    var bin1 = hextobin(hex1);
    var bin2 = hextobin(hex2);
    var xor = new Uint8Array(bin1.length);
    for (i = 0; i < xor.length; i++){
        xor[i] = bin1[i] ^ bin2[i];
    }
    return bintohex(xor);
}

function swapEndian(hex){
    if (hex.length % 2 !== 0){return "length must be a multiple of 2!";}
    var data = "";
    for (var i=1; i <= hex.length / 2; i++){
        data += hex.substr(0 - 2 * i, 2);
    }
    return data;
}

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
    if (netbyte === "11"){
        var hs = rand_16();
        var mn = mn_encode(hs, mnDictTag.value);
        var privSk = sc_reduce32(hs);
        var pubSk = sec_key_to_pub(privSk);
        var privVk = sc_reduce32(cn_fast_hash(pubSk));
        var pubVk = sec_key_to_pub(privVk);
    } else {
        var hs = rand_16();
        var mn = mn_encode(hs, mnDictTag.value);
        var privSk = sc_reduce32(cn_fast_hash(hs));
        var privVk = sc_reduce32(cn_fast_hash(cn_fast_hash(hs)));
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

function encryptMn(encrypt){
    var mn = (encrypt) ? mn_decode(mnemonic.value, mnDictTag.value) : mn_decode(encMnTag.value, mnDictTag.value);
    var pass = encKeyTag.value;
    if (encrypt){
        encMnTag.value = "Encrypting...";
    } else {
        mnemonic.value = "Decrypting...";
    }
    setTimeout(function (encrypt, mn, pass){
        var key = bintohex(SlowHash.string(pass));
        var mnResult = mn_encode(hex_xor(mn, key.slice(0, mn.length)));
        if (encrypt){
            encMnTag.value = mnResult;
        } else {
            mnemonic.value = mnResult;
        }
    }, 50, encrypt, mn, pass);
}

function deriveAddr(){
    derivedAddrTag.value = "";
    if (addrPt2Tag.value === ""){
        return;
    }
    try{
        var keys = decode_address(addrPt2Tag.value);
    }
    catch(err){
        derivedAddrTag.value = err;
        return;
    }
    var pass = encKey2Tag.value;
    derivedAddrTag.value = "Calculating...";
    setTimeout(function (keys, pass){
        var scalar = sc_reduce32(bintohex(SlowHash.string(pass)));
        var pub2 = sec_key_to_pub(scalar);
        var derivedPub = ge_add(keys.spend, pub2);
        derivedAddrTag.value = pubkeys_to_string(derivedPub, keys.view);
    }, 50, keys, pass);
}

function derive2faKeys(){
    derivedSpendKeyTag.value = "";
    derivedViewKeyTag.value = "";
    if (mnemonicPt2Tag.value === ""){
        return;
    }
    try{
        var scalar1 = sc_reduce32(mn_decode(mnemonicPt2Tag.value)); //ensure seed is reduced
    }
    catch(err){
        derivedSpendKeyTag.value = err;
        return;
    }
    var pass = encKey2Tag.value;
    derivedAddrTag.value = "Calculating...";
    setTimeout(function (scalar1, pass){
        var scalar2 = sc_reduce32(bintohex(SlowHash.string(pass)));
        var spendKey = sc_add(scalar1, scalar2);
        var viewKey = sc_reduce32(cn_fast_hash(scalar1));
        derivedAddrTag.value = pubkeys_to_string(sec_key_to_pub(spendKey), sec_key_to_pub(viewKey));
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
    for (i = 0; i < coinTypeTag.getElementsByTagName('option').length; i++){
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


//for checktx.html
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
        if (addrHex.slice(66,130) !== sec_key_to_pub(sec)){
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
    if (typeTag.value === "Private Viewkey"){
        var extra = parseExtra(res.transaction_data.extra);
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
    for (i = 0; i < outputNum; i++){
        var pubkey = derive_public_key(der, i, spk);
        if (pubkey === res.transaction_data.vout[i].target.key){
            tot += res.transaction_data.vout[i].amount;
            console.log("You own output " + i + " with pubkey: " + pubkey + " for amount: " + res.transaction_data.vout[i].amount / 1000000000000);
            resultsTag.innerHTML += "<span class='validYes'>This address owns output&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + i + " with pubkey: " + pubkey + " for amount: " + res.transaction_data.vout[i].amount / 1000000000000 + "</span>" + "<br>"; //amount / 10^12
        } else {
            console.log("You don't own output " + i + " with pubkey: " + res.transaction_data.vout[i].target.key + " for amount: " + res.transaction_data.vout[i].amount / 1000000000000);
            resultsTag.innerHTML += "<span class='validNo'>This address doesn't own output " + i + " with pubkey: " + res.transaction_data.vout[i].target.key + " for amount: " + res.transaction_data.vout[i].amount / 1000000000000 + "</span>" + "<br>"; //amount / 10^12
        }
    }
    resultsTag.innerHTML += "<br>" + "Total received: " + tot / 1000000000000; //10^12
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
    verifyMessage.value = "-----BEGIN MONERO SIGNED MESSAGE-----" + "\n" + msg + "\n" + "Address: " + address + "\n" + "-----BEGIN SIGNATURE-----" + "\n" + sig + "\n" + "-----END MONERO SIGNED MESSAGE-----";
    return;
}

function verifyMsg(){
    verifyResultTag.innerHTML = "Checking...";
    setTimeout(function(){
        var message = verifyMessage.value;
        message = message.split("\n");
        if (message.length === 6 && message[0] === "-----BEGIN MONERO SIGNED MESSAGE-----"){
            var hash = keccak_256(message[1]);
            if (message[2].slice(0,8) === "Address:"){
                var address = message[2].slice(8,9) === " " ? message[2].slice(9) : message[2].slice(8);
            } else if ((message[2].length === 95 || message[2].length === 106) && message[2].slice(0,1) === "4"){
                var address = message[2];
            } else {
                verifyResultTag.innerHTML = "<span class='validNo'>Your address could not be parsed!</span>";
                return;
            }
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
        var result = bintohex(SlowHash.hex(data));
        document.getElementById('slowHashOut').value = result;
    }, 0, data);
}