# UdonSharpCryptography

A small cyptographyc package for UdonSharp.

## APIs

### Hash algorithms

* SHA-1
  * `XiPHiA.Cryptography.SHA1.ComputeHash(byte[] message): byte[]`
* SHA-2
  * `XiPHiA.Cryptography.SHA256.ComputeHash(byte[] message): byte[]`
  * `XiPHiA.Cryptography.SHA512.ComputeHash(byte[] message): byte[]`
* HMAC
  * `XiPHiA.Cryptography.HMACSHA1.ComputeHash(byte[] message, byte[] secret): byte[]`
  * `XiPHiA.Cryptography.HMACSHA256.ComputeHash(byte[] message, byte[] secret): byte[]`
  * `XiPHiA.Cryptography.HMACSHA512.ComputeHash(byte[] message, byte[] secret): byte[]`

### Utility static methods

* string to UTF8 byte array (like `System.Text.Encoding.UTF8.GetBytes(string s)`)
  * `XiPHiA.Cryptography.DataUtil.GetBytes(string message): byte[]`
