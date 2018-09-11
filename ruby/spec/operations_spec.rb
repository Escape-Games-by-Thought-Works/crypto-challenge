require 'operations'

RSpec.describe Operations do
  describe '#xor' do
    it 'xors two integers' do
      result = Operations.xor(0b1001, 0b1010)
      expect(result).to eq(0b0011)
    end
  end

  describe '#add' do
    it 'adds two integers' do
      result = Operations.add(5, 2)
      expect(result).to eq(7)
    end

    it 'performs the addition modulo 2^16' do
      result = Operations.add(0xf123, 0x1234)
      expect(result).to eq(0x0357)
    end
  end

  describe '#mult' do
    it 'has 0x0001 as identity element' do
      expect(Operations.mult(0x1234, 0x0001)).to eq(0x1234)
      expect(Operations.mult(0x0000, 0x0001)).to eq(0x0000)
      expect(Operations.mult(0xffff, 0x0001)).to eq(0xffff)
    end

    it 'performs the multiplication modulo 2^16 + 1' do
      expect(Operations.mult(0xffff, 0x0002)).to eq(0xfffd)
    end

    it 'treats 0x0000 special' do
      expect(Operations.mult(0x0000, 0x0000)).to eq(1)
    end

    it 'treats result special if it is 0x10000' do
      expect(Operations.mult(0x0004, 0x4000)).to eq(0)
    end
  end
end
