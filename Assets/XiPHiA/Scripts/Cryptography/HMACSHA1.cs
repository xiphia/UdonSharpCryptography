namespace XiPHiA.Scripts.Cryptography
{
    public static class HMACSHA1
    {
        public static byte[] ComputeHash(byte[] message, byte[] secret)
        {
            var key = new byte[64];
            if (64 < secret.Length)
            {
                SHA1.ComputeHash(secret).CopyTo(key, 0);
            }
            else
            {
                secret.CopyTo(key, 0);
            }
            return SHA1.ComputeHash(key.Xor(0x5C).Concat(SHA1.ComputeHash(key.Xor(0x36).Concat(message))));
        }
    }
}
