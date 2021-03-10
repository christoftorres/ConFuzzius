pragma solidity ^0.4.26;

interface Token {
  function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
  function allowance(address owner, address spender) external view returns (uint256);
}

contract TokenSale {
  uint256 start = now;
  uint256 end = now + 30 days;
  address wallet = 0xCafEBAbECAFEbAbEcaFEbabECAfebAbEcAFEBaBe;
  Token token = Token(0x1234567812345678123456781234567812345678);

  address owner;
  bool sold;

  function Tokensale() public {
    owner = msg.sender;
  }

  function buy() public payable {
    require(now < end);
    require(msg.value == 42 ether + (now - start) / 60 / 60 / 24 * 1 ether);
    require(token.transferFrom(this, msg.sender, token.allowance(wallet, this)));
    sold = true;
  }

  function withdraw() public {
    require(msg.sender == owner);
    require(now >= end);
    require(sold);
    owner.transfer(address(this).balance);
  }
}
