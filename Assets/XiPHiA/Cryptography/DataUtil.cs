using System;
using UdonSharp;

namespace XiPHiA.Cryptography
{
    public class DataUtil : UdonSharpBehaviour
    {
        public static byte[] UnicodeToUTF8Bytes(char c)
        {
            var code = Convert.ToUInt32(c);
            if (code < 0x00000080)
            {
                return new [] { (byte)code };
            }
            if (code < 0x00000800)
            {
                var c0 = 0b11000000 | (code >> 6 & 0b00011111);
                var c1 = 0b10000000 | (code & 0b00111111);
                return new [] { (byte)c0, (byte)c1 };
            }
            if (code < 0x00010000)
            {
                var c0 = 0b11100000 | (code >> 12 & 0b00001111);
                var c1 = 0b10000000 | (code >> 6 & 0b00111111);
                var c2 = 0b10000000 | (code & 0b00111111);
                return new [] { (byte)c0, (byte)c1, (byte)c2 };
            }
            if (code < 0x00110000)
            {
                var c0 = 0b11110000 | (code >> 18 & 0b00000111);
                var c1 = 0b10000000 | (code >> 12 & 0b00111111);
                var c2 = 0b10000000 | (code >> 6 & 0b00111111);
                var c3 = 0b10000000 | (code & 0b00111111);
                return new [] { (byte)c0, (byte)c1, (byte)c2, (byte)c3 };
            }
            return new byte[] {};
        }
        
        public static byte[] GetBytes(string message)
        {
            var buffer = new byte[message.Length * 4];
            var chars = message.ToCharArray();
            var pos = 0;
            foreach (var c in chars)
            {
                var bytes = UnicodeToUTF8Bytes(c);
                bytes.CopyTo(buffer, pos);
                pos += bytes.Length;
            }
            var result = new byte[pos];
            Array.Copy(buffer, 0, result, 0, pos);
            return result;
        }
    }
}
