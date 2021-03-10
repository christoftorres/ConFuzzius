pragma solidity ^0.4.25;

contract TimedCrowdsale {

  event Finished();
  event notFinished();

  // Sale should finish exactly at January 1, 2019
  function isSaleFinished() private returns (bool) {
    return block.timestamp >= 1546300800;
  }

  function run(address a) public {
  	if (isSaleFinished()) {
      a.transfer(address(this).balance);
  		emit Finished();
  	} else {
  		emit notFinished();
  	}
  }

}
