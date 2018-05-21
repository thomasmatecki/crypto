import os
import json
import time
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from authenticated.fernet import Fernet


def modfied_url_safe(data, fr=0, to=None):
  """
  :param data:
  :return:
  """
  if not to:
    to = len(data)

  return data[:fr] + data[fr: to].replace("+", "-").replace("/", "_") + data[to:]


def modfied_url_unsafe(data, fr=0, to=None):
  """
  :param data:
  :param fr:
  :param to:
  :return:
  """
  if not to:
    to = len(data)

  return data[:fr] + data[fr: to].replace("-", "+").replace("_", "/") + data[to:]


def decode_keyring(key_ring):
  """
  :param key_ring:
  :return:
  """
  key_ring = {k: modfied_url_unsafe(v).replace("+++++", "-----")
              for k, v
              in key_ring.items()}

  return key_ring


def load_public_keyring(public_keystring):
  """
  :param public_keystring:
  :return:
  """
  return {group: decode_keyring(keyring)
          for group, keyring
          in json.loads(public_keystring).items()}


class KeyProtocol:
  def __init__(self, public_keys, private_keys, backend=None):
    self.backend = backend
    self.private_keys = private_keys
    self.public_keys = public_keys

    self.EC_CURVES = {
      "prime192v1": ec.SECP192R1,
      "prime256v1": ec.SECP256R1,

      "secp192r1": ec.SECP192R1,
      "secp224r1": ec.SECP224R1,
      "secp256r1": ec.SECP256R1,
      "secp384r1": ec.SECP384R1,
      "secp521r1": ec.SECP521R1,
      "secp256k1": ec.SECP256K1,

      "sect163k1": ec.SECT163K1,
      "sect233k1": ec.SECT233K1,
      "sect283k1": ec.SECT283K1,
      "sect409k1": ec.SECT409K1,
      "sect571k1": ec.SECT571K1,

      "sect163r2": ec.SECT163R2,
      "sect233r1": ec.SECT233R1,
      "sect283r1": ec.SECT283R1,
      "sect409r1": ec.SECT409R1,
      "sect571r1": ec.SECT571R1,
    }

  def _get_pk(self, key_alias):
    public_key_pem = self.public_keys.get(key_alias)

    if not public_key_pem:
      raise LookupError("Key %s not found" % key_alias)

    public_key = serialization.load_pem_public_key(
      str(public_key_pem),  # convert from unicode
      backend=self.backend)

    return public_key

  def _get_sk(self, key_alias):
    private_key_pem = self.private_keys.get(key_alias)

    if not private_key_pem:
      raise LookupError("Key %s not found" % key_alias)

    private_key = serialization.load_pem_private_key(
      str(private_key_pem),  # convert from unicode
      password=None,
      backend=self.backend)

    return private_key


class KeyExchangeProtocol(KeyProtocol):
  def encryption_key_combo(self, param, version):
    raise NotImplementedError()

  def decryption_symmetric_key(self, param, version, KxPk):
    raise NotImplementedError()


class RSAKeyExchange(KeyExchangeProtocol):

  def encryption_key_combo(self, param, version):
    """
    :param param:
    :param version:
    :return:
    """

    rsakx_peer_key = self._get_pk('rsa.%s.%s.enc.pub' % (param, version))

    random_secret = os.urandom(32)

    fernet_key = base64.urlsafe_b64encode(random_secret)

    rsakx_public_key = rsakx_peer_key.encrypt(random_secret,
                                              padding.OAEP(
                                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                algorithm=hashes.SHA256(),
                                                label=None))

    return base64.urlsafe_b64encode(rsakx_public_key), fernet_key

  def decryption_symmetric_key(self, param, version, KxPk):
    """
    :param param:
    :param version:
    :param KxPk:
    :return:
    """
    rsakx_secret_key = self._get_sk('rsa.%s.%s.enc.priv' % (param, version))

    random_secret = base64.urlsafe_b64decode(KxPk)

    fernet_key = rsakx_secret_key.decrypt(random_secret,
                                          padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None))

    return base64.urlsafe_b64encode(fernet_key)


class ECCKeyExchange(KeyExchangeProtocol):

  def encryption_key_combo(self, param, version):
    """
    :param param:
    :param version:
    :return:
    """

    eckxa_peer_key = self._get_pk('ecc.%s.%s.enc.pub' % (param, version))

    ec_curve = self.EC_CURVES[param]

    eckxa_ephemeral_key = ec.generate_private_key(
      ec_curve(), self.backend
    )

    ec_shared_key = eckxa_ephemeral_key.exchange(ec.ECDH(), eckxa_peer_key)

    fernet_key = HKDF(
      algorithm=hashes.SHA256(),
      length=32,
      salt=None,
      info='',
      backend=self.backend
    ).derive(ec_shared_key)

    eckxa_public_key = eckxa_ephemeral_key.public_key()

    fernet_key = base64.urlsafe_b64encode(fernet_key)

    eckxa_public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return eckxa_public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo), fernet_key

  def decryption_symmetric_key(self, param, version, KxPk):
    eckxa_private_key = self._get_sk('ecc.%s.%s.enc.priv' % (param, version))

    ephemeral_key = serialization.load_pem_public_key(
      KxPk,  # convert from unicode
      backend=self.backend)

    ec_shared_key = eckxa_private_key.exchange(ec.ECDH(), ephemeral_key)

    fernet_key = HKDF(
      algorithm=hashes.SHA256(),
      length=32,
      salt=None,
      info='',
      backend=self.backend
    ).derive(ec_shared_key)

    fernet_key = base64.urlsafe_b64encode(fernet_key)

    return fernet_key


class DigitalSignatureScheme(KeyProtocol):
  """

  """
  HASHES = {
    "md5": hashes.MD5,
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512
  }

  def __init__(self, public_keys, private_keys, backend=None):
    KeyProtocol.__init__(self, public_keys, private_keys, backend=None)
    self.key_template = None

  def _hash_function(self, hash_alg):
    hash_function = self.HASHES[hash_alg]
    return hash_function()

  def sign(self, param, version, message, hash_alg):
    signing_key = self._get_sk(self.key_template % (param, version, 'priv'))

    signature = signing_key.sign(
      message,
      self._hash_function(hash_alg)
    )

    return signature

  def verify(self, param, version, message, signature, hash_alg):
    """
    :param param:
    :param version:
    :param message:
    :param signature:
    :return:
    """
    peer_signing_key = self._get_pk(self.key_template % (param, version, 'pub'))

    peer_signing_key.verify(
      signature,
      message,
      self._hash_function(hash_alg)
    )


class ECCDigitalSignature(KeyProtocol, DigitalSignatureScheme):
  key_template = 'ecc.%s.%s.sig.%s'

  def _hash_function(self, hash_alg):
    hash_function = self.HASHES[hash_alg]
    return ec.ECDSA(hash_function())


class DSADigitalSignature(KeyProtocol, DigitalSignatureScheme):
  key_template = 'dsa.%s.%s.sig.%s'


class RSADigitalSignature(KeyProtocol, DigitalSignatureScheme):

  def sign(self, param, version, message, hash_alg):
    """

    :param param:
    :param version:
    :param message:
    :param hash_alg:
    :return:
    """
    signing_key = self._get_sk('rsa.%s.%s.sig.priv' % (param, version))

    signature = signing_key.sign(
      message,
      padding.PSS(
        mgf=padding.MGF1(
          self._hash_function(hash_alg)),
        salt_length=padding.PSS.MAX_LENGTH
      ),
      self._hash_function(hash_alg)
    )

    return signature

  def verify(self, param, version, message, signature, hash_alg):
    """

    :param param:
    :param version:
    :param message:
    :param signature:
    :param hash_alg:
    :return:
    """

    peer_signing_key = self._get_pk('rsa.%s.%s.sig.pub' % (param, version))

    peer_signing_key.verify(
      signature,
      message,
      padding.PSS(
        mgf=padding.MGF1(self._hash_function(hash_alg)),
        salt_length=padding.PSS.MAX_LENGTH),
      self._hash_function(hash_alg)
    )

    return


class PKFernet:

  def __init__(self, private_keystring, public_keystring):
    """

    :param private_keystring:
    :param public_keystring:
    """
    self.private_keys = decode_keyring(
      json.loads(private_keystring)
    )

    self.public_keys = load_public_keyring(public_keystring)

    self.backend = default_backend()

    self.key_exchange_protocols = {
      'ecc': ECCKeyExchange,
      'rsa': RSAKeyExchange
    }
    self.digital_signature_protocols = {
      'ecdsa': ECCDigitalSignature,
      'rsa': RSADigitalSignature,
      'dsa': DSADigitalSignature
    }

  def encrypt(self, msg, receiver_name, receiver_enc_pub_key_alias, sender_sign_header, sign_also=True):
    """

    :param receiver_enc_pub_key_alias:
    :param msg:
    :param receiver_name:
    :param sender_sign_header:
    :param sign_also:
    :return:
    """
    kx_algorithm, param, version = receiver_enc_pub_key_alias.split(".")

    receiver_public_keys = self.public_keys[receiver_name]

    key_exchange_protocol = self.key_exchange_protocols[kx_algorithm]

    key_exchanger = key_exchange_protocol(
      receiver_public_keys,
      self.private_keys,
      backend=self.backend
    )

    kx_cipher_key, fernet_key = key_exchanger.encryption_key_combo(param, version)

    symmetric_cipher = Fernet(
      fernet_key,
      backend=self.backend
    )

    ds_algorithm, param, version = sender_sign_header.split(".")

    sign_alg, hash_alg = ds_algorithm.split("_with_")

    digital_signature_protocol = self.digital_signature_protocols[sign_alg]

    if sign_also:
      digital_signer = digital_signature_protocol(
        self.public_keys[receiver_name],
        self.private_keys,
        backend=self.backend
      )

      signature = digital_signer.sign(param, version, msg, hash_alg)

    else:
      signature = ""

    fernet_plaintext = "|".join(map(base64.urlsafe_b64encode, [msg, sender_sign_header, signature]))

    fernet_ciphertext = symmetric_cipher.encrypt(fernet_plaintext)

    return "|".join([
      base64.urlsafe_b64encode(receiver_enc_pub_key_alias),
      kx_cipher_key,
      fernet_ciphertext])

  def decrypt(self, ciphertext, sender_name, verify_also=True):
    """
    :param ciphertext:
    :param sender_name:
    :return:
    """

    enc_pub_key_alias, kx_public_key, fernet_ciphertext = ciphertext.split("|")

    enc_pub_key_alias = base64.urlsafe_b64decode(enc_pub_key_alias)

    kx_algorithm, param, version = enc_pub_key_alias.split(".")

    key_exchange_protocol = self.key_exchange_protocols[kx_algorithm]

    key_exchanger = key_exchange_protocol(
      self.public_keys[sender_name],
      self.private_keys,
      backend=self.backend
    )

    kx_public_key = modfied_url_unsafe(kx_public_key, 27, -25)

    fernet_key = key_exchanger.decryption_symmetric_key(param, version, kx_public_key)

    symmetric_cipher = Fernet(
      fernet_key,
      backend=self.backend
    )

    plaintext = symmetric_cipher.decrypt(fernet_ciphertext)

    plaintext = modfied_url_unsafe(plaintext)

    message, digital_signature_header, signature = map(
      base64.urlsafe_b64decode,
      plaintext.split("|")
    )

    # Verify Digital Signature
    if verify_also:
      ds_algorithm, param, version = digital_signature_header.split(".")

      verify_alg, hash_alg = ds_algorithm.split("_with_")

      digital_signature_protocol = self.digital_signature_protocols[verify_alg]

      digital_signer = digital_signature_protocol(
        self.public_keys[sender_name],
        self.private_keys,
        backend=self.backend
      )

      digital_signer.verify(param, version, message, signature, hash_alg)

    return message

  def export_pub_keys(self, key_alias_list=None):
    """
    Export the public keys with the <receiver_name> e.g {receiver_name: {ecc..: <PEM_KEY>} } into the json format for
    the keys with the one given in this list of aliases. If key_alias_list is empty it will export all the public
    keys of the private keys in @priv_keyring.

    :param key_alias_list:
    :return:
    """

    def modified_url_safe_public_key(private_pem_key):
      private_key = serialization.load_pem_private_key(
        str(private_pem_key),
        password=None,
        backend=self.backend)

      public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
      )

      return modfied_url_safe(public_key_pem)

    if key_alias_list is None:
      # all public keys for this private keyring
      key_string = json.dumps({
        key_alias.replace("priv", "pub"): modified_url_safe_public_key(private_pem_key)
        for key_alias, private_pem_key
        in self.private_keys.items()
      })

    else:

      key_string = json.dumps({
        key_alias: json.dumps({
          header: modfied_url_safe(pem_key)
          for header, pem_key
          in self.public_keys[key_alias].items()
        })
        for key_alias
        in set(key_alias_list)
      })

    key_ring_file = open("keyring_export_%d.json" % int(time.time()), 'w')

    key_ring_file.write(key_string)

    key_ring_file.close()

    return key_string

  def import_pub_keys(self, receiver_name, receiver_public_keyring):
    """
    Import public keys of a friend (receiver) into the PKFernet object's. The receiver_public_keyring dictionary
    object can contain public keys for multiple receivers, but this method will only import the keys associated with
    the receiver_name parameter.

    :param receiver_name:
    :param receiver_public_keyring: a dictionary object containing keyrings indexed by receiver name
    """
    self.public_keys[receiver_name] = receiver_public_keyring[receiver_name]
