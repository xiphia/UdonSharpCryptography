namespace XiPHiA.Scripts.Cryptography
{
    public static class HMACSHA512
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
            return SHA512.ComputeHash(key.Xor(0x5C).Concat(SHA512.ComputeHash(key.Xor(0x36).Concat(message))));
        }
    }
}
