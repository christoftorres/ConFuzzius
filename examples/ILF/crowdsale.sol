contract Crowdsale {

  uint256 goal = 100000 * (10**18);
  uint256 phase = 0; // 0: Active, 1: Success, 2: Refund
  uint256 raised;
  uint256 end;
  address owner;
  mapping(address => uint256) investments;

  constructor() public {
    end = now + 60 days;
    owner = msg.sender;
  }

  function invest() public payable {
    require(phase == 0 && raised < goal);
    investments[msg.sender] += msg.value;
    raised += msg.value;
  }

  function setPhase(uint256 newPhase) public {
    require(
      (newPhase == 1 && raised >= goal) ||
      (newPhase == 2 && raised < goal && now > end)
    );
    phase = newPhase;
  }

  function setOwner(address newOwner) public {
    // Fix: require(msg.sender == owner);
    owner = newOwner;
  }

  function withdraw() public {
    require(phase == 1);
    owner.transfer(raised);
  }

  function refund() public {
    require(phase == 1);
    msg.sender.transfer(investments[msg.sender]);
    investments[msg.sender] = 0;
  }

}
