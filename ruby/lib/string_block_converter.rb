class StringBlockConverter
  def split64(block64)
    [block64 >> 48,
     (block64 >> 32) & 0xffff,
     (block64 >> 16) & 0xffff,
     block64 & 0xffff]
  end

  def join64(four_blocks)
    four_blocks[0] << 48 |
      four_blocks[1] << 32 |
      four_blocks[2] << 16 |
      four_blocks[3]
  end

  def join_string(blocks64)
    parts = blocks64.map do |block|
      str = ''
      for i in 0..7
        single_block = (block >> (56 - i * 8)) & 0xff
        if single_block != 0
          str += single_block.chr
        end
      end
      str
    end

    parts.join()
  end

  def str_to_blocks(str)
    blocks = []
    for i in 0.step(str.bytesize - 1, 8)
      block = 0
      for j in 0..7
        if i + j < str.bytesize
          block |= str.getbyte(i + j) << (56 - (j * 8))
        end
      end
      blocks.push(block)
    end
    blocks
  end
end
