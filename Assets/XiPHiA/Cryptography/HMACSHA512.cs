using UdonSharp;

namespace XiPHiA.Cryptography
{
    public class HMACSHA512 : UdonSharpBehaviour
    {
        public static byte[] ComputeHash(byte[] message, byte[] secret)
        {
            var key = new byte[128];
            if (128 < secret.Length)
            {
                SHA512.ComputeHash(secret).CopyTo(key, 0);
            }
            else
            {
                secret.CopyTo(key, 0);
            }
            return SHA512.ComputeHash(HashOps.Concat(HashOps.Xor(key, 0x5C), SHA512.ComputeHash(HashOps.Concat(HashOps.Xor(key, 0x36), message))));
        }
    }
}
