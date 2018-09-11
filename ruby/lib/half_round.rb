require 'operations'

class HalfRound

  def initialize(keys)
    @keys = keys
  end

  def run(blocks)
    [Operations.mult(@keys[0], blocks[0]),
     Operations.add(@keys[1], blocks[1]),
     Operations.add(@keys[2], blocks[2]),
     Operations.mult(@keys[3], blocks[3])]
  end
end
