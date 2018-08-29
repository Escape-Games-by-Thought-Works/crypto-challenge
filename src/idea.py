"""Implement the IDEA algorithm in python manually"""

class Block(int):
    """Implement IDEA's addition, multiplication, and xor group arithmetic"""
    def __add__(self, x):
        return Block(int.__add__(self, x) % (1 << 16))

    def __mul__(self, x):
        return Block(int.__mul__(self, x) % ((1 << 16) + 1))

    def __xor__(self, x):
        return Block(int.__xor__(self, x))

    def m_inv(self):
        """Compute the multiplicative inverse modulo 2**16 + 1"""
        if self == 0:
            return Block(1 << 16)
        _p = ((1 << 16) + 1)
        return Block(int.__pow__(self, (_p - 2)) % _p)

    def a_inv(self):
        """Compute the additive inverse modulo 2**16"""
        return Block(int.__sub__((1 << 16), self) % (1 << 16))

class IDEA():
    """Implement the IDEA encryption algorithm"""
    def __init__(self, key, n_rounds=8):
        self.key = key
        self.n_rounds = n_rounds
        self.subkeys = []

        for _ in range(self.n_rounds):
            self.subkeys.extend(self._get_subkeys())
            self.key = self._rot_l(25, 128)

    def _rot_l(self, n_bits, width=128):
        """Left circular bit shift"""
        mask = (2**width - 1)
        n_bits = n_bits % width
        return ((self.key << n_bits) & mask) | \
               ((self.key & mask) >> (width - n_bits))

    def _get_subkeys(self):
        """Break the key into 8 subkeys"""
        return [Block(self._rot_l(16 * (i + 1), 128) & 0xFFFF)
                for i in range(8)]

    def _encrypt_block(self, block):
        sub_blocks = IDEA.create_sub_blocks(block)
        for iteration in range(self.n_rounds):
            idx = 6 * iteration
            subkeys = self.subkeys[idx:idx + 6]
            swap_outs = iteration < self.n_rounds - 1
            sub_blocks = IDEA.idea_round(sub_blocks, subkeys, swap_outs)

        # Always end with a half-step
        output = IDEA.half_step(sub_blocks, self.subkeys[48:52])

        # combine the remaining blocks to get the encrypted 64-bit message
        return sum([output[i] << (16 * (3 - i)) for i in range(len(output))])

    @staticmethod
    def make_64bit_block(c_bytes):
        """Turn 1 to 8 separate bytes into a 64 bit block"""
        assert len(c_bytes) <= 8
        c_bytes = list(c_bytes)
        # If we have less than 8 bytes, pad it out to 8 bytes using 0x10[00]...
        if len(c_bytes) < 8:
            c_bytes.extend([0x10])
        while len(c_bytes) < 8:
            c_bytes.extend([0x00])

        return sum([(c_bytes[i] << (8 * (7 - i))) for i in range(8)])

    @staticmethod
    def create_sub_blocks(block):
        """Break a 64-bit block into four 16-bit words"""
        mask = 0xFFFF
        return [Block((block >> 16 * (3 - i)) & mask) for i in range(4)]

    @staticmethod
    def string_to_blocks(message):
        """Convert a message into unencrypted 64-bit blocks"""
        msg_bytes = message.encode('utf-8')
        # break the message into 64-bit blocks
        blocks = [IDEA.make_64bit_block(msg_bytes[idx:idx + 8])
                  for idx in range(0, len(message), 8)]
        return blocks

    @staticmethod
    def blocks_to_string(blocks):
        """Convert a list of unencrypted 64-bit blocks to a string"""
        return ''.join([bytearray([block >> (8 * (7 - i)) & 0xFF
                                   for i in range(8)]).decode('utf-8')
                        for block in blocks])

    @staticmethod
    def half_step(words, subkeys):
        """Execute the first half of the IDEA round"""
        return [subkeys[0] * words[0],
                subkeys[1] + words[1],
                subkeys[2] + words[2],
                subkeys[3] * words[3]]

    @staticmethod
    def idea_round(words, subkeys, swap_outs=True):
        """Compute one round of the IDEA algorithm"""
        # Compute the first half-step
        _s = IDEA.half_step(words, subkeys[0:4])

        # if it's a full round, compute the remaining bits
        # This computation is used twice, so we'll store it
        _x = (_s[0] ^ _s[2]) * subkeys[4]
        _y = (_x + (_s[1] ^ _s[3])) * subkeys[5]
        _z = _x + _y

        # On the last round, we don't want to swap the outputs
        if swap_outs:
            return [_s[0] ^ _y, _s[2] ^ _y, _s[1] ^ _z, _s[3] ^ _z]

        return [_s[0] ^ _y, _s[1] ^ _z, _s[2] ^ _y, _s[3] ^ _z]

    def encrypt(self, message):
        """Encrypt a message with the key given at object initialization"""
        blocks = IDEA.string_to_blocks(message)
        return [self._encrypt_block(block) for block in blocks]
