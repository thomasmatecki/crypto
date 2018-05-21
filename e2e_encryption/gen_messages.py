from pk_fernet import PKFernet
import time

private_keyring_file = open('./private_keyring.json')
private_keystring = private_keyring_file.read()

public_keyring_file = open('./public_keyring.json')
public_keystring = public_keyring_file.read()

pk_fernet = PKFernet(private_keystring, public_keystring)

receivers = [
  "Siqiu",
  "thomas",
  "Stephen",
  "Jonathan",
  "liran",
  "rongxin",
  "zeeshan",
  "Vicente",
  "zen",
  "Matt2",
  "Feston2"
]

for receiver in receivers:
  cipher_text = pk_fernet.encrypt(
    "hello %s" % receiver, receiver, "ecc.secp224r1.1", "rsa_with_sha512.2048.1"
  ).replace("\n", "\\n")

  message_file = open("messages/to_%s_%d.txt" % (receiver, int(time.time())), 'w')
  message_file.write(cipher_text)
  message_file.close()
