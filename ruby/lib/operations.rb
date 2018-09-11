class Operations
  def self.xor(a, b)
    a ^ b
  end

  def self.add(a, b)
    (a + b) & 0xffff
  end

  def self.mult(a, b)
    a = a == 0 ? 0x10000 : a
    b = b == 0 ? 0x10000 : b
    result = (a * b) % (2 ** 16 + 1)

    result & 0xffff
  end
end
