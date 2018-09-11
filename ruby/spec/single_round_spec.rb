require 'inner_round'
require 'half_round'
require 'swap_round'
require 'key_scheduler'
require 'operations'

RSpec.describe 'rounds' do
  skip 'encrypts and decrypts correctly in regular round' do
    input_blocks = [0x0123, 0x4567, 0x89ab, 0xcdef]
    key_scheduler = KeyScheduler.for_key(0xabab00edefEE111234D08152CCCC3333)
    enc_keys1 = key_scheduler.encrypt_keys(2)
    enc_keys2 = key_scheduler.encrypt_keys(3)
    dec_keys1 = key_scheduler.decrypt_keys(5)
    dec_keys2 = key_scheduler.decrypt_keys(6)

    enc_rounds = [
      HalfRound.new(enc_keys1),
      InnerRound.new(enc_keys1),
      HalfRound.new(enc_keys2)
    ]

    dec_rounds = [
      HalfRound.new(dec_keys1),
      InnerRound.new(dec_keys1),
      HalfRound.new(dec_keys2)
    ]

    encrypted_blocks = enc_rounds.reduce(input_blocks) {|blocks, round| round.run(blocks)}
    decrypted_blocks = dec_rounds.reduce(encrypted_blocks) {|blocks, round| round.run(blocks)}

    expect(decrypted_blocks).to eq(input_blocks)
  end

  skip 'encrypts and decrypts correctly with two rounds' do
    input_blocks = [0x0123, 0x4567, 0x89ab, 0xcdef]
    key_scheduler = KeyScheduler.for_key(0xabab00edefEE111234D08152CCCC3333)
    enc_keys1 = key_scheduler.encrypt_keys(2)
    enc_keys2 = key_scheduler.encrypt_keys(3)
    enc_keys3 = key_scheduler.encrypt_keys(4)
    dec_keys1 = key_scheduler.decrypt_keys(4)
    dec_keys2 = key_scheduler.decrypt_keys(5)
    dec_keys3 = key_scheduler.decrypt_keys(6)

    swap = SwapRound.new
    enc_rounds = [
      HalfRound.new(enc_keys1),
      InnerRound.new(enc_keys1),
      swap,
      HalfRound.new(enc_keys2),
      InnerRound.new(enc_keys2),
      HalfRound.new(enc_keys3)
    ]

    dec_rounds = [
      HalfRound.new(dec_keys1),
      InnerRound.new(dec_keys1),
      swap,
      HalfRound.new(swap.run(dec_keys2)),
      InnerRound.new(dec_keys2),
      HalfRound.new(dec_keys3)
    ]

    encrypted_blocks = enc_rounds.reduce(input_blocks) {|blocks, round| round.run(blocks)}
    decrypted_blocks = dec_rounds.reduce(encrypted_blocks) {|blocks, round| round.run(blocks)}

    expect(decrypted_blocks).to eq(input_blocks)
  end
end
