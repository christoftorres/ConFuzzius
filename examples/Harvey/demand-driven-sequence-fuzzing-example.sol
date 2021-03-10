contract Foo {
  int256 private x;
  int256 private y;

  function Foo() public {
    x = 0;
    y = 0;
  }

  function Bar() public view returns (int256) {
    if (x == 42) {
      assert(false);
      return 1;
    }
    return 0;
  }

  function SetY(int256 ny) public { y = ny; }

  function IncX() public { x++; }

  function CopyY() public { x = y; }
}
