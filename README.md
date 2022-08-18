# UdonSharpCryptography

A small cryptographic package for UdonSharp.

## APIs

### Hash algorithms

* SHA-1
  * `XiPHiA.Scripts.Cryptography.SHA1.ComputeHash(byte[] message): byte[]`
* SHA-2
  * `XiPHiA.Scripts.Cryptography.SHA256.ComputeHash(byte[] message): byte[]`
  * `XiPHiA.Scripts.Cryptography.SHA512.ComputeHash(byte[] message): byte[]`
* HMAC
  * `XiPHiA.Scripts.Cryptography.HMACSHA1.ComputeHash(byte[] message, byte[] secret): byte[]`
  * `XiPHiA.Scripts.Cryptography.HMACSHA256.ComputeHash(byte[] message, byte[] secret): byte[]`
  * `XiPHiA.Scripts.Cryptography.HMACSHA512.ComputeHash(byte[] message, byte[] secret): byte[]`

### Utility extension methods

`XiPHiA.Scripts.Utility.ExtensionMethods`

* string to UTF8 byte array (like `System.Text.Encoding.UTF8.GetBytes(string s)`)
  * `string.ToUTF8ByteArray(string message): byte[]`
* integer to byte array (`int`, `uint`, `long`, `ulong`)
  * `int.ToByteArray(this int data, bool reverse = false): byte[]`
  * `uint.ToByteArray(this uint data, bool reverse = false): byte[]`
  * `long.ToByteArray(this long data, bool reverse = false): byte[]`
  * `ulong.ToByteArray(this ulong data, bool reverse = false): byte[]`

