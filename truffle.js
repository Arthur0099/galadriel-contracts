require('babel-register');
require('babel-polyfill');

module.exports = {
  compilers: {
    solc: {
      settings: {
        evmVersion: "byzantium",
      }
    }
  },
  networks: {
    development: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "*",
      gas: 80000000,
    },
    local: {
      host: "192.168.1.115",
      port: 8545,
      network_id: "*",
      gas: 800000000,
    }
  }
};