# crypto-challenge

Clues to help save Alex are all around you! For this clue, Alex has conveniently left her email username entered into the laptop, but you need to recover the password.

Nearby, you should find a paper with a series of hexadecimal numbers printed on it. From what you know of Alex, this is probably a clue to getting access to her email. You know that Alex has been studying cryptography, and she's left behind an implementation of the [IDEA](https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm) algorithm. The only problem is that she never finished implementing the decryption step!

Maybe you can help her out! Implement the IDEA decryption algorithm and see if it reveals her hidden password!

## About the IDEA algorithm

IDEA is what is known as a _symmetric-key block cipher_. It's simple to break down what that means:

- _symmetric-key_ means the same key used to encrypt the data is also used to decrypt it;
- _block-cipher_ means the algorithm works on _block_ of a fixed number of bits.

In this case, IDEA uses a 128-bit key and operates on 64-bit blocks. The way it operates is as follows:

1. First, a message is broken into unencrypted 64-bit blocks. If the message length isn't evenly divisible by 64, then the last block is _padded_ to ensure it makes the full 64-bits.
2. Next, the 128-bit key is turned into 56 _subkeys_ using a rotation algorithm. Each subkey is a 16-bit _word_.
3. The algorithm works in _rounds_. Each round is a complex algorithm that does some math to combine the subkeys with each block to obtain a new result. Each round has two major steps: the first half-step, which mixes the block with 4 subkeys; and then a mixture step that uses two additional subkeys to scramble the message even further. The outputs of each round are used as the inputs to the next round.
4. At the end of 8 rounds, the first half-step is executed one more time.
5. The resulting output is four 16-bit words, which are then recombined into a 64-bit encrypted block.

The cleverness of the IDEA cipher comes from the fact that the same algorithm is used for decryption, but instead it takes the _inverse_ of the subkeys and applies them in a slightly different order. This means that the same code used to encrypt a message can be used to decrypt it, using a variation on the same key.

## Your task

Finish Alex's work by implementing the IDEA decryption algorithm. She's done a lot of the work for you and has structured her code to make it as easy as possible. She's also left some unit tests that show how her algorithm works.

### The `Word` class

The IDEA algorithm works using special variations of addition, multiplication, and bitwise xor. The `Word` class is a subclass of `int` that implements these operations using the normal `+`, `*`, and `^` operators as expected (the last operator is python's bitwise xor operation!) In addition, the `Word` class implements two methods: `m_inv()` and `a_inv()` which compute the multiplicative and additive inverses of a 16-bit block number for you. You will need to make use of these methods when computing the subkeys.

### The `IDEA` class

The IDEA class has all the implementation necessary to encrypt a message using the IDEA algorithm. It is simple to use:

```python
message = "My message"
key = 0x2BD6459F82C5B300952C49104881FF48
my_idea = IDEA(key)
my_idea.encrypy(message)
```

However, the class has exposed some properties and static methods that will make it easier to implement decryption. The static methods are:

- `make_64bit_block(c_bytes)`: takes an array of up to 8 bytes and turns it into a 64-bit integer, padding as necessary.
- `create_sub_blocks(block)`: Takes a 64-bit integer and turns it into 16-bit `Word`s. This is a convenience method.
- `string_to_blocks(message)`: Turns a string into a list of 64-bit blocks. This is used to take a plaintext string and put it into the data structure required by the IDEA algorithm
- `blocks_to_string(blocks)`: The opposite of the above method. Recovers a string from a list of unencrypted 64-bit blocks.
- `half_step(words, subkeys)`: Given a list of four `Word`s and the appropriate subkeys, this computes the first half-step of an IDEA round.
- `idea_round(words, subkeys, swap_outs)`: Given four `Word`s and the appropriate subkeys, this computes an entire round of the IDEA algorithm. On the final round, we don't swap the outputs, so a flag is also included as a parameter.
- `subkeys`: This is a list of the subkeys, K0 through K51, used in the encryption and decryption process. Each subkey belongs to the class `Word`, so you can compute the additive and multiplicative inverses easily if you need.

### Helpful information

Implement the decryption step of the IDEA algorithm. To do this, you will need to do the following:

- Accurately compute the 52 subkeys used for decryption (more below);
- Implement the 8.5 rounds of IDEA using the above static methods;
- Reassemble the resulting 64-bit blocks into the message.

Important notes: `half_step` and `idea_round` will always take four 16-bit `Word`s as the first input argument. `half_step` uses four subkeys starting from the first element in the provided list; `idea_round` implements `half_step`, using those four subkeys, and also uses two more subkeys in its mixture step, for a total of 6.

For encryption, each round uses six subkeys, and these subkeys are not used in subsequent rounds. For example the first encryption round uses subkeys K1, K2, K3, K4, K5, and K6. The first half-step uses K1 through K4, while K5 and K6 are used for the mixture step.

For decryption, the subkeys for decryption are derived as follows:

- For the first half-step, take the four subkeys used in the _last_ half-step of the encryption round. (For the second round, take the subkeys used in the second to last round, etc).
- Compute the multiplicative inverse for the first and fourth subkeys. Compute the additive inverse for the second and third.
- For all decryption half-steps except for the first and last, switch the second and third subkeys.
- For the first mixture step, take the two subkeys used in the last mixture step (respectively for 2nd and 2nd to last, etc.)
- These will now be the six subkeys you need for the first full decryption round.

Remember: after 8 full rounds, we only do a half-step, so we only need 4 subkeys.

The following images should be helpful.

![IDEA encryption](images/idea_encrypt.png)
![IDEA_decryption](images/idea_decrypt.png)
