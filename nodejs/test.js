var multiHashing = require('bindings')('multihashing.node')

var data = new Buffer("010000000000000000000000000000000000000000000000000000000000000000000000e9d2350e20e3b9fb412a4f72e8602f331a77eede6dc200c2771d6cd1a4dd5f1834ece15affff7f1ee3ce0100", "hex");

var hashedData = multiHashing.x11evo(data, 1, 4096, 1);
var algos = [
    "c11", "x11", "x12", "x13", "x14", "x15", "x17", "x11evo", "xevan", "x16r", "x16s",
    "timetravel", "bitcore", "hsr", "hmq1725", "jha", "allium", "lyra2", "lyra2v2", "lyra2z", "bastion",
    "blake", "blake2s", "vanilla", "decred", "deep", "fresh", "quark", "qubit", "nist5", "groestl", "skein",
    "sonoa", "tribus", "keccak", "keccakc", "phi", "phi2", "polytimos", "skunk", "bmw", "luffa", "penta",
    "zr5", "veltor", "vitalium", "aergo", "sib", "whirlpoolx", "scrypt", "scryptn", "neoscrypt"
];


for(var i = 0; i < algos.length; i++) {
   var algo = algos[i];
   var hashedData = multiHashing[algo](data, 1, 4096, 1);
   console.log("Algo: " + algo + " Hash: " + hashedData.toString('hex'));
}
