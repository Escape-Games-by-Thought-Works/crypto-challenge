"""Decrypt Alex's password to escape the room!"""
import unittest
from idea import IDEA, Word

class DecryptionTest(unittest.TestCase):
    """Unit Tests to help you decrypt Alex's message"""
    def test_block_message(self):
        """This test is here to show you how messages get broken into
        64-bit blocks
        """
        blocks = ['0x5065746572207069',
                  '0x706572207069636b',
                  '0x6564206120706563',
                  '0x6b206f6620706963',
                  '0x6b65642070657070',
                  '0x6572731000000000']

        self.assertEqual(sorted(blocks),
                         sorted([hex(v) for v in IDEA.string_to_blocks(MESSAGE)]))

    def test_idea_half_step(self):
        """Test the first half-step of the IDEA algorithm on a single block"""
        blocks = IDEA.string_to_blocks(MESSAGE)
        words = IDEA.create_sub_blocks(blocks[0])

        my_idea = IDEA(KEY)
        subkeys = my_idea.subkeys[0:4]

        half_step = ['0x1daa', '0xba04', '0xf4e5', '0x1c67']
        self.assertEqual(sorted(half_step),
                         sorted([hex(v) for v in IDEA.half_step(words, subkeys)]))

    def test_idea_round(self):
        """Test a single round of IDEA on a single block"""
        blocks = IDEA.string_to_blocks(MESSAGE)
        words = IDEA.create_sub_blocks(blocks[0])

        my_idea = IDEA(KEY)
        subkeys = my_idea.subkeys[0:6]
        round_results = ['0x936b', '0x7a24', '0xa167', '0x704']

        self.assertEqual(round_results,
                         [hex(v) for v in my_idea.idea_round(words, subkeys, True)])

    def test_encryption(self):
        """Test the encryption of a message"""
        my_idea = IDEA(KEY)
        self.assertEqual(ENCRYPTED_MESSAGE,
                         [hex(v) for v in my_idea.encrypt(MESSAGE)])


KEY = 0x2BD6459F82C5B300952C49104881FF48
MESSAGE = "Peter piper picked a peck of picked peppers"
ENCRYPTED_MESSAGE = ['0xeb9ffebced6abe6d',
                     '0xd7869756f01dea5b',
                     '0x909025bea8fbf146',
                     '0xfaab92aa70f67156',
                     '0x69bf22ba12c95436',
                     '0xc33d28a1e6e5a003']

if __name__ == "__main__":
    unittest.main()
