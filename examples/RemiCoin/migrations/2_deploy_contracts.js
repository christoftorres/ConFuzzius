var RemiCoin = artifacts.require("RemiCoin");

module.exports = function(deployer) {
  deployer.deploy(RemiCoin, 8400000000000000, "RemiCoin", "RMC", 8);
};
