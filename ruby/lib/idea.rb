require 'key_scheduler'
require 'half_round'
require 'inner_round'
require 'swap_round'
require 'string_block_converter'
require 'base64'

class IDEA

  def initialize(key)
    @key_scheduler = KeyScheduler.for_key(key)
    @converter = StringBlockConverter.new
  end

  def encrypt_string(string)
    encrypted_blocks = @converter.str_to_blocks(string)
      .map { |b| @converter.split64(b) }
      .map { |b| encrypt_block(b) }

    Base64.strict_encode64(@converter.join_string(encrypted_blocks.flatten))
  end

  def decrypt_string(input_str)
    blocks = @converter.str_to_blocks(Base64.decode64(input_str))

    blocks64 = blocks
      .map { |block64| @converter.split64(block64) }
      .map { |four_blocks| decrypt_block(four_blocks) }
      .map { |four_blocks| @converter.join64(four_blocks) }
    @converter.join_string(blocks64)
  end

  def encrypt_block(four_blocks)
    round_keys = (0..8).map { |round_idx| @key_scheduler.encrypt_keys(round_idx) }
    rounds = round_keys.each.with_index.flat_map do |keys, idx|
      if idx == 8
        [HalfRound.new(keys)]
      elsif idx == 0
        [HalfRound.new(keys),
         InnerRound.new(keys)]
      else
        [swap,
         HalfRound.new(keys),
         InnerRound.new(keys)]
      end
    end
    return execute_rounds(rounds, four_blocks)
  end

  private
  def swap
    SwapRound.new
  end

  def execute_rounds(rounds, four_blocks)
    rounds.reduce(four_blocks) {|blocks, round| round.run(blocks)}
  end
end
