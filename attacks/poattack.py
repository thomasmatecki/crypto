from paddingoracle import PaddingOracle


def split_into_blocks(msg, l):
  while msg:
    yield msg[:l]
    msg = msg[l:]


def oracle_attacker(po, c1):
  """
  For a padding oracle and block of cipher text, return a function that
  reveals all bytes of the cipher ext for a given pad length and previous
  block. In the case of two block CBC, this function takes a padded
  block and returns a function that will return the message for a given pad
  length and initialization vector.
  :param po:
  :param c1:
  :return:
  """

  def _attack_block(pad_len, c0):
    """
    Given the number of padding bytes, increment value of each padding byte
    by 1 and determine the padding byte value that will create a valid message
    with `pad_len + 1` padding bytes. This `byte_value` can then be used to
    leak a single byte from the message; i.e.:

        rightmost non-padding byte XOR `byte_value` XOR `pad_len + 1`

    :param pad_len:
    :param c0:
    :return:
    """
    pad_xb = (pad_len + 1) ^ pad_len
    pad_fr = 16 - pad_len - 1

    xv_tail = bytearray(ord(cb) ^ pad_xb for cb in c0[pad_fr + 1:])

    # Find a byte value that generates a valid padding in the next block:
    for byte_value in range(0, 256):
      ivj = c0[:pad_fr] + bytearray([byte_value]) + xv_tail
      ctxj = str(ivj + c1)

      if po.decrypt(ctxj):
        msg_bytes = bytearray([ord(c0[pad_fr]) ^ byte_value ^ (pad_len + 1)])

        if pad_fr == 0:
          return msg_bytes
        else:
          prev_bytes = _attack_block(pad_len + 1, str(ivj))
          if prev_bytes:
            return prev_bytes + msg_bytes

  return _attack_block


def po_attack_2blocks(po, ctx):
  """Given two blocks of cipher texts, it can recover the first block of
  the message.
  @po: an instance of padding oracle.
  @ctx: a ciphertext generated using po.setup()
  Don't unpad the message.
  """
  assert len(ctx) == 2 * po.block_length, "This function only accepts 2 block " \
                                          "cipher texts. Got {} block(s)!".format(len(ctx) / po.block_length)

  c0, c1 = list(split_into_blocks(ctx, po.block_length))

  attack = oracle_attacker(po, c1)

  # Determine the number of padding bytes in the second block
  i = 16
  for i in range(i, -1, -1):
    # Check if the last byte of the message is between 1 and 16...
    c0i = str(bytearray(c0[:15]) + bytearray([ord(c0[15]) ^ i ^ 1]))

    # ...if it is, then query padding oracle with `i` padding bytes...
    if po.decrypt(c0i + c1):
      break

  # If padding with `i` bytes doesn't work, then the message ends
  # with `i` but has no padding.
  msg_bytes = attack(i, c0) or attack(0, c0)

  return str(msg_bytes)


def po_attack(po, ctx):
  """
  Padding oracle attack that can decrypt any arbitrary length message.
  @po: an instance of padding oracle.
  @ctx: a ciphertext generated using po.setup()
  You don't have to unpad the message.
  """
  ctx_blocks = list(split_into_blocks(ctx, po.block_length))
  nblocks = len(ctx_blocks)

  res = ""
  for i in range(1, nblocks - 1):
    attack = oracle_attacker(po, ctx_blocks[i])
    block = attack(0, ctx_blocks[i - 1])
    res += str(block)
  res += po_attack_2blocks(po, ctx_blocks[-2] + ctx_blocks[-1])
  return res


################################################################################
##### me.thomas.crypto.Tests
################################################################################

def test_po_attack_2blocks():
  for i in xrange(1, 16):
    po = PaddingOracle(msg_len=i)
    ctx = po.setup()
    msg = po_attack_2blocks(po, ctx)
    assert po.test(msg), "Failed 'po_attack_2blocks' for msg of length={}".format(i)


def test_po_attack():
  for i in xrange(1000):
    po = PaddingOracle(msg_len=i)
    ctx = po.setup()
    msg = po_attack(po, ctx)
    assert po.test(msg), "Failed 'po_attack' for msg of length={}".format(i)


if __name__ == "__main__":
  test_po_attack_2blocks()
  test_po_attack()
