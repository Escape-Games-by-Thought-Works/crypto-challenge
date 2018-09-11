require 'operations'

class InnerRound

  def initialize(keys)
    @keys = keys
  end

  def run(blocks)
    left_xor1 = Operations.xor(blocks[0], blocks[2])
    right_xor1 = Operations.xor(blocks[1], blocks[3])

    middle_top_left = Operations.mult(@keys[4], left_xor1)
    middle_top_right = Operations.add(middle_top_left, right_xor1)

    middle_bottom_right = Operations.mult(middle_top_right, @keys[5])
    middle_bottom_left = Operations.add(middle_top_left, middle_bottom_right)

    [
      Operations.xor(blocks[0], middle_bottom_right),
      Operations.xor(blocks[1], middle_bottom_left),
      Operations.xor(middle_bottom_right, blocks[2]),
      Operations.xor(middle_bottom_left, blocks[3])
    ]
  end

end
