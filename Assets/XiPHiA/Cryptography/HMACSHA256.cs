using UdonSharp;

namespace XiPHiA.Cryptography
{
    public class HMACSHA256 : UdonSharpBehaviour
    {
        public static byte[] ComputeHash(byte[] message, byte[] secret)
        {
            var key = new byte[64];
            if (64 < secret.Length)
            {
                SHA256.ComputeHash(secret).CopyTo(key, 0);
            }
            else
            {
                secret.CopyTo(key, 0);
            }
            return SHA256.ComputeHash(HashOps.Concat(HashOps.Xor(key, 0x5C), SHA256.ComputeHash(HashOps.Concat(HashOps.Xor(key, 0x36), message))));
        }
    }
}
