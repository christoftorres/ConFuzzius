contract Grid {

  struct Pixel { address owner; uint256 price; }
  address admin;
  mapping(address => uint256) pending;
  Pixel[1000][1000] pixels;
  uint256 public defaultPrice;

  function Grid() public {
    admin = msg.sender;
    defaultPrice = 2 * 10 ** 15;
  }

  function setDefaultPrice(uint256 price) {
    require(admin == msg.sender);
    defaultPrice = price;
  }

  function buyPixel(uint16 row, uint16 col) public payable {
    var (owner, price) = getPixelInfo(row, col);
    require(msg.value >= price);
    pending[owner] += msg.value;
    pixels[row][col].owner = msg.sender;
  }

  function withdraw() public {
    uint256 amount = pending[msg.sender];
    pending[msg.sender] = 0;
    msg.sender.transfer(amount);
  }

  function getPixelInfo(uint16 row, uint16 col) public returns (address, uint256) {
    Pixel pixel = pixels[row][col];
    if (pixel.owner == 0) return (admin, defaultPrice);
    return (pixel.owner, pixel.price);
  }

}
