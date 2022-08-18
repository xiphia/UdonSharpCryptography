using UdonSharp;

namespace XiPHiA.Cryptography
{
    public class HashOps : UdonSharpBehaviour
    {
        public static byte[] UIntToBytes(uint data)
        {
            return new[]
            {
                (byte)(data & 0xFF),
                (byte)(data >> 8 & 0xFF),
                (byte)(data >> 16 & 0xFF),
                (byte)(data >> 24 & 0xFF),
            };
        }
        
        public static byte[] ULongToBytes(ulong data)
        {
            return new[]
            {
                (byte)(data & 0xFF),
                (byte)(data >> 8 & 0xFF),
                (byte)(data >> 16 & 0xFF),
                (byte)(data >> 24 & 0xFF),
                (byte)(data >> 32 & 0xFF),
                (byte)(data >> 40 & 0xFF),
                (byte)(data >> 48 & 0xFF),
                (byte)(data >> 56 & 0xFF),
            };
        }
        
        public static byte[] IntToBytes(int data)
        {
            return new[]
            {
                (byte)(data & 0xFF),
                (byte)(data >> 8 & 0xFF),
                (byte)(data >> 16 & 0xFF),
                (byte)(data >> 24 & 0xFF),
            };
        }
        
        public static byte[] LongToBytes(long data)
        {
            return new[]
            {
                (byte)(data & 0xFF),
                (byte)(data >> 8 & 0xFF),
                (byte)(data >> 16 & 0xFF),
                (byte)(data >> 24 & 0xFF),
                (byte)(data >> 32 & 0xFF),
                (byte)(data >> 40 & 0xFF),
                (byte)(data >> 48 & 0xFF),
                (byte)(data >> 56 & 0xFF),
            };
        }
        
        public static uint LeftRotate32(uint word, int shift)
        {
            return (word << shift) | (word >> (32 - shift));
        }
        
        public static uint RightRotate32(uint word, int shift)
        {
            return (word >> shift) | (word << (32 - shift));
        }
        
        public static ulong LeftRotate64(ulong word, int shift)
        {
            return (word << shift) | (word >> (64 - shift));
        }
        
        public static ulong RightRotate64(ulong word, int shift)
        {
            return (word >> shift) | (word << (64 - shift));
        }
        
        public static uint GetWordFromBytes(byte[] source, int index)
        {
            return (uint)source[index] << 24 & 0xFF000000 |
                   ((uint)source[index + 1] << 16 & 0x00FF0000) |
                   ((uint)source[index + 2] << 8 & 0x0000FF00) |
                   ((uint)source[index + 3] & 0x000000FF);
        }
        
        public static ulong GetDoubleWordFromBytes(byte[] source, int index)
        {
            return (ulong)source[index] << 56 & 0xFF00000000000000 |
                   ((ulong)source[index + 1] << 48 & 0x00FF000000000000) |
                   ((ulong)source[index + 2] << 40 & 0x0000FF0000000000) |
                   ((ulong)source[index + 3] << 32 & 0x000000FF00000000) |
                   ((ulong)source[index + 4] << 24 & 0x00000000FF000000) |
                   ((ulong)source[index + 5] << 16 & 0x0000000000FF0000) |
                   ((ulong)source[index + 6] << 8 & 0x000000000000FF00) |
                   ((ulong)source[index + 7] & 0x00000000000000FF);
        }

        public static byte[] Concat(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            a.CopyTo(result, 0);
            b.CopyTo(result, a.Length);
            return result;
        }

        public static byte[] Xor(byte[] a, byte b)
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
