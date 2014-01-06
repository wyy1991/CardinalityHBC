#!/usr/bin/env python
# Copyright 2012 Google Inc. All Rights Reserved.

"""Paillier encryption to perform homomorphic addition on encrypted data."""



import ctypes
import ctypes.util
import math
import platform
import struct

from Crypto.Util import number

import logging

import common_crypto as ccrypto


N_LENGTH = 128  # bits
HALF_N_LENGTH = N_LENGTH / 2  # bits
MAX_INT64 = (2 ** 63) -1
MIN_INT64 = -(2 ** 63)
_ONES_33 = long(33*'1', 2)
_ONES_63 = long(63*'1', 2)
_ONES_64 = long(64*'1', 2)
_ONES_96 = long(96*'1', 2)
_ONES_832 = long(832*'1', 2)
# Bit positions of various sections in expanded float representation created
# from an IEEE float value; (assumes starting bit is numbered as 1).

MAX_ADDS = 32  # (bits) i.e. if < 2^32 adds occur than overflow can be detected

EXPLICIT_MANTISSA_BITS = 52
MANTISSA_BITS = 53
EXPONENT_BITS = 11
EXPONENT_BIAS = (2 ** (EXPONENT_BITS - 1)) - 1  # 1023 for 11 bit exponent


# -- openssl function args and return types
_FOUND_SSL = False
try:
  if platform.system() == 'Windows':
    ssl_libpath = ctypes.util.find_library('libeay32')
  else:
    ssl_libpath = ctypes.util.find_library('ssl')
  if ssl_libpath:
    ssl = ctypes.cdll.LoadLibrary(ssl_libpath)
    _FOUND_SSL = True
  else:
    logging.info('Could not find open ssl library; paillier encryption '
                 'during load will be slower')
except (OSError, IOError):
  logging.info('Could not find open ssl library; paillier encryption '
               'during load will be slower')
if _FOUND_SSL:
  ssl.BN_new.restype = ctypes.c_void_p
  ssl.BN_new.argtypes = []
  ssl.BN_free.argtypes = [ctypes.c_void_p]
  ssl.BN_num_bits.restype = ctypes.c_int
  ssl.BN_num_bits.argtypes = [ctypes.c_void_p]
  ssl.BN_bin2bn.restype = ctypes.c_void_p
  ssl.BN_bin2bn.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
  ssl.BN_bn2bin.restype = ctypes.c_int
  ssl.BN_bn2bin.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
  ssl.BN_CTX_new.restype = ctypes.c_void_p
  ssl.BN_CTX_new.argtypes = []
  ssl.BN_CTX_free.restype = ctypes.c_int
  ssl.BN_CTX_free.argtypes = [ctypes.c_void_p]
  ssl.BN_mod_exp.restype = ctypes.c_int
  ssl.BN_mod_exp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                             ctypes.c_void_p, ctypes.c_void_p]


class Paillier(object):
  """Class for paillier encryption/decryption and homomorphic addition.

  Also includes methods to encrypt/decrypt signed int64 and float numbers.
  """

  def __init__(self, seed=None, g=None, n=None, Lambda=None, mu=None):
    """Intialize Paillier object with seed.

    Args:
      seed: str used to generate key - derives paillier parameters including
        g, n, lambda, and mu; if set to None then paillier parameters have to be
        explicitly provided which is useful in testing.
      g: Long integer, has to be provided if seed is None.
      n: Long integer, has to be provided if seed is None.
      Lambda: Long integer, has to be provided if seed is None.
      mu: Long integer, has to be provided if seed is None.

    Raises:
      ValueError: When seed is None yet one of the g, n, Lambda, mu parameters
        is not provided.
    """
    if seed is None:
      # initialization of these values directly is useful for testing purposes.
      if not (g and n and Lambda and mu):
        raise ValueError('If seed is set to none then g, n, Lambda and mu'
                         ' need to be provided.')
      self.n = n
      self.nsquare = n * n
      self.g = g
      self.__lambda = Lambda
      self.__mu = mu
      return
    if not isinstance(seed, str):
      raise ValueError('Expected string type data for seed, but got: %s' %
                       type(seed))
    if not seed:
      raise ValueError('Provided seed cannot be empty')
    prg = ccrypto.PRG(seed)
    n_len = 0
    while n_len != N_LENGTH:
      p = number.getPrime(HALF_N_LENGTH, prg.GetNextBytes)
      q = number.getPrime(HALF_N_LENGTH, prg.GetNextBytes)
      self.n = p * q
      n_len = len(bin(self.n)) - 2  # take 2 out for '0b' prefix
    self.nsquare = self.n * self.n
    # Simpler paillier variant with g=n+1 results in lamda equal to phi
    # and mu is phi inverse mod n.
    self.g = self.n + 1
    phi_n = (p-1) * (q-1)
    self.__lambda = phi_n
    self.__mu = number.inverse(phi_n, self.n)
    
  def getLambda(self):
      return self.__lambda
  def getMu(self):
      return self.__mu

  def Encrypt(self, plaintext, r_value=None):
    """Paillier encryption of plaintext.

    Args:
      plaintext: an integer or long to be paillier encrypted.
      r_value: random value used in encryption, in default case (i.e. r_value
        is None) the value is supplied by the method.

    Returns:
      a long, representing paillier encryption of plaintext.

    Raises:
      ValueError: if plaintext is neither int nor long.
    """

    if not isinstance(plaintext, int) and not isinstance(plaintext, long):
      raise ValueError('Expected int or long type plaintext but got: %s' %
                       type(plaintext))
    r = r_value or self._GetRandomFromZNStar(N_LENGTH, self.n)
    return (ModExp(self.g, plaintext, self.nsquare) *
            ModExp(r, self.n, self.nsquare)) % self.nsquare

  def Decrypt(self, ciphertext):
    """Paillier decryption of ciphertext.

    Args:
      ciphertext: a long that is to be paillier decrypted.

    Returns:
      a long, representing paillier decryption of ciphertext.

    Raises:
      ValueError: if ciphertext is neither int nor long.
    """
    if not isinstance(ciphertext, int) and not isinstance(ciphertext, long):
      raise ValueError('Expected int or long type ciphertext but got: %s' %
                       type(ciphertext))
    u = ModExp(ciphertext, self.__lambda, self.nsquare)
    l_of_u = (u - 1) // self.n
    return (l_of_u * self.__mu) % self.n

  # TODO(user): use a pluggable random generator here and other places to test
  # more of the code base.
  def _GetRandomFromZNStar(self, n_length, n):
    while True:
      r = number.getRandomNumber(n_length, ccrypto.GetRandBytes)
      # check relative prime
      if r < n and number.GCD(r, n) == 1:
        break
    return r

  def Add(self, ciphertext1, ciphertext2):
    """returns E(m1 + m2) given E(m1) and E(m2).

    Args:
      ciphertext1: a long whose paillier decryption is to be added.
      ciphertext2: a long whose paillier decryption is to be added.

    Returns:
      a long as the modular product of the two ciphertexts which is equal to
        E(m1 + m2).

    Raises:
      ValueError: if either ciphertext is neither int nor long.
    """
    for c in (ciphertext1, ciphertext2):
      if not isinstance(c, int) and not isinstance(c, long):
        raise ValueError('Expected int or long type for %s but got %s' %
                         (c, type(c)))
    return ciphertext1 * ciphertext2 % self.nsquare

  def Affine(self, ciphertext, a=1, b=0):
    """Returns E(a*m + b) given E(m), a and b."""
    # This works for raw paillier payload but may not for int64/float payload.
    # First multiply ciphertext with a
    a_mult_ciphertext = pow(ciphertext, a, self.nsquare)
    # Add b to it.
    return a_mult_ciphertext * pow(self.g, b, self.nsquare) % self.nsquare

  def EncryptInt64(self, plaintext, r_value=None):
    """Paillier encryption of an Int64 plaintext.

    Paillier homomorphic addition only directly adds positive values, however,
    we would like to add both positive and negative values (i.e. int64 is
    signed). To achieve this, we will represent negative values with twos
    complement representation. Also, in order to detect overflow after adding
    multiple values, the 64 sign bit is extended (or replicated) all the way to
    the 96th bit and bits above 96 are all zeroes.

    Args:
      plaintext: a 64 bit int or long to be encrypted with values from -2^63
        to 2^63 - 1.
      r_value: random value used in encryption, in default case (i.e None) the
        value is supplied by the method.

    Returns:
      a long, representing paillier encryption of an int64 plaintext.

    Raises:
      ValueError: if not an int nor long, or less than MIN_INT64 or more than
        MAX_INT64.
    """
    if not isinstance(plaintext, int) and not isinstance(plaintext, long):
      raise ValueError('Expected int or long plaintext but got: %s' %
                       type(plaintext))
    if plaintext < MIN_INT64 or plaintext > MAX_INT64:
      raise ValueError('Int64 values need to be between %d and %d but got %d'
                       % (MIN_INT64, MAX_INT64, plaintext))
    plaintext = self._Extend64bitTo96bitTwosComplement(plaintext)
    return self.Encrypt(plaintext, r_value=r_value)

  def _Extend64bitTo96bitTwosComplement(self, num):
    if num >= 0:
      # positive number is extended by just adding zeroes.
      return num
    # negative number, make 96 bit 2s complement
    return (abs(num) ^ _ONES_96) + 1L

  def DecryptInt64(self, ciphertext):
    """Paillier decryption of ciphertext into a int64 value.

    Args:
      ciphertext: a long that is to be paillier decrypted into int64.

    Returns:
      a long, representing paillier decryption of ciphertext into an int64 value

    Raises:
      ValueError: if either ciphertext is neither int nor long.
      OverflowError: if overflow is detected in the decrypted int.
    """
    if not isinstance(ciphertext, int) and not isinstance(ciphertext, long):
      raise ValueError('Expected int or long type ciphertext but got: %s' %
                       type(ciphertext))
    plaintext = self.Decrypt(ciphertext)
    valuebits1to63 = plaintext & _ONES_63  # lsb is numbered as bit 1 here.
    signbits64to96 = (plaintext & 0xffffffff8000000000000000L) >> 63
    if not (signbits64to96 == 0 or signbits64to96 == _ONES_33):
      raise OverflowError('Overflow detected in decrypted int')
    if signbits64to96 == 0:
      return  valuebits1to63
    # negative number case
    # - first find the positive value of the number by taking the 2s complement
    #   of the 96 bit (likely greater) integer.
    positive_96bit_value = (plaintext ^ _ONES_96) + 1L
    # - final value will mostly be a 63 bit number or smaller except if -2^63
    #   which gives 64 bit value 2^63.
    positive_64bit_value = positive_96bit_value & _ONES_64
    return -1 * positive_64bit_value


def IsNan(x):
  return math.isnan(x)


def IsInfPlus(x):
  return math.isinf(x) and x > 0


def IsInfMinus(x):
  return math.isinf(x) and x < 0


def _NumBytesBn(bn):
  """Returns the number of bytes in the Bignum."""
  if not _FOUND_SSL:
    raise RuntimeError('Cannot evaluate _NumBytesBn because ssl library was '
                       'not found')
  size_in_bits = ssl.BN_num_bits(bn)
  return int(math.ceil(size_in_bits / 8.0))


def ModExp(a, b, c):
  """Uses openssl, if available, to do a^b mod c where a,b,c are longs."""
  if not _FOUND_SSL:
    return pow(a, b, c)
  # convert arbitrary long args to bytes
  bytes_a = number.long_to_bytes(a)
  bytes_b = number.long_to_bytes(b)
  bytes_c = number.long_to_bytes(c)

  # convert bytes to (pointer to) Bignums.
  bn_a = ssl.BN_bin2bn(bytes_a, len(bytes_a), 0)
  bn_b = ssl.BN_bin2bn(bytes_b, len(bytes_b), 0)
  bn_c = ssl.BN_bin2bn(bytes_c, len(bytes_c), 0)
  bn_result = ssl.BN_new()
  ctx = ssl.BN_CTX_new()

  # exponentiate and convert result to long
  ssl.BN_mod_exp(bn_result, bn_a, bn_b, bn_c, ctx)
  num_bytes_in_result = _NumBytesBn(bn_result)
  bytes_result = ctypes.create_string_buffer(num_bytes_in_result)
  ssl.BN_bn2bin(bn_result, bytes_result)
  long_result = number.bytes_to_long(bytes_result.raw)

  # clean up
  ssl.BN_CTX_free(ctx)
  ssl.BN_free(bn_a)
  ssl.BN_free(bn_b)
  ssl.BN_free(bn_c)
  ssl.BN_free(bn_result)

  return long_result
