var multiHashing = require('bindings')('multihashing.node')

var data = new Buffer("010000000000000000000000000000000000000000000000000000000000000000000000e9d2350e20e3b9fb412a4f72e8602f331a77eede6dc200c2771d6cd1a4dd5f1834ece15affff7f1ee3ce0100", "hex");

var hashedData = multiHashing.x11(data, 1, 4096, 1);

console.log(hashedData.toString('hex'));
