namespace XiPHiA.Scripts.Cryptography
{
    public static class HashOps
    {
        public static uint LeftRotate(this uint word, int shift)
        {
            return (word << shift) | (word >> (32 - shift));
        }
        
        public static uint RightRotate(this uint word, int shift)
        {
            return (word >> shift) | (word << (32 - shift));
        }
        
        public static ulong LeftRotate(this ulong word, int shift)
        {
            return (word << shift) | (word >> (64 - shift));
        }
        
        public static ulong RightRotate(this ulong word, int shift)
        {
            return (word >> shift) | (word << (64 - shift));
        }
        
        public static uint GetUInt(this byte[] source, int index = 0, bool reverse = false)
        {
            return (uint)source[index + (reverse ? 3 : 0)] << 24 & 0xFF000000 |
                   ((uint)source[index + (reverse ? 2 : 1)] << 16 & 0x00FF0000) |
                   ((uint)source[index + (reverse ? 1 : 2)] << 8 & 0x0000FF00) |
                   ((uint)source[index + (reverse ? 0 : 3)] & 0x000000FF);
        }
        
        public static ulong GetULong(this byte[] source, int index = 0, bool reverse = false)
        {
            return (ulong)source[index + (reverse ? 7 : 0)] << 56 & 0xFF00000000000000 |
                   ((ulong)source[index + (reverse ? 6 : 1)] << 48 & 0x00FF000000000000) |
                   ((ulong)source[index + (reverse ? 5 : 2)] << 40 & 0x0000FF0000000000) |
                   ((ulong)source[index + (reverse ? 4 : 3)] << 32 & 0x000000FF00000000) |
                   ((ulong)source[index + (reverse ? 3 : 4)] << 24 & 0x00000000FF000000) |
                   ((ulong)source[index + (reverse ? 2 : 5)] << 16 & 0x0000000000FF0000) |
                   ((ulong)source[index + (reverse ? 1 : 6)] << 8 & 0x000000000000FF00) |
                   ((ulong)source[index + (reverse ? 0 : 7)] & 0x00000000000000FF);
        }

        public static byte[] Concat(this byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            a.CopyTo(result, 0);
            b.CopyTo(result, a.Length);
            return result;
        }

        public static byte[] Xor(this byte[] a, byte b)
        {
            var result = new byte[a.Length];
            var length = result.Length;
            for (var i = 0; i < length; i++)
            {
                result[i] = (byte)(a[i] ^ b);
            }
            return result;
        }
    }
}
