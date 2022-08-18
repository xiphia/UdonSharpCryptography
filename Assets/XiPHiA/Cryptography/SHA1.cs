using System;
using UdonSharp;

namespace XiPHiA.Cryptography
{
    public class SHA1 : UdonSharpBehaviour
    {
        private static void PrepareWords(byte[] chunk, uint[] words)
        {
            for (var i = 0; i < 16; i++)
            {
                words[i] = HashOps.GetWordFromBytes(chunk, i * 4);
            }
            for (var i = 16; i < 80; i++)
            {
                words[i] = HashOps.LeftRotate32(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
            }
        }

        private static int CalcChunkSize(int length)
        {
            var minimalDataLength = length + 9;
            var adjustment = minimalDataLength % 64 == 0 ? 0 : 1;
            return minimalDataLength / 64 + adjustment;
        }

        private static byte[] PadMessage(byte[] message)
        {
            var messageLength = message.Length;
            var chunks = CalcChunkSize(messageLength);
            var paddedLength = chunks * 64;
            var paddedMessage = new byte[paddedLength];
            message.CopyTo(paddedMessage, 0);
            paddedMessage[messageLength] = 0x80;
            var reverseLength = HashOps.IntToBytes(messageLength * 8);
            Array.Reverse(reverseLength);
            reverseLength.CopyTo(paddedMessage, paddedLength - 4);
            return paddedMessage;
        }

        private static void CalcState(uint[] chunkHash, uint[] words, int round)
        {
            var f =
                round < 20 ? (chunkHash[1] & chunkHash[2]) | (~chunkHash[1] & chunkHash[3]) :
                round < 40 ?  chunkHash[1] ^ chunkHash[2] ^ chunkHash[3]:
                round < 60 ? (chunkHash[1] & chunkHash[2]) | (chunkHash[1] & chunkHash[3]) | (chunkHash[2] & chunkHash[3]) :
                chunkHash[1] ^ chunkHash[2] ^ chunkHash[3];
            var k = new uint[]
            {
                0x5A827999,
                0x6ED9EBA1,
                0x8F1BBCDC,
                0xCA62C1D6
            };
            var temp = HashOps.LeftRotate32(chunkHash[0], 5) + f + chunkHash[4] + k[round / 20] + words[round];
            chunkHash[4] = chunkHash[3];
            chunkHash[3] = chunkHash[2];
            chunkHash[2] = HashOps.LeftRotate32(chunkHash[1], 30);
            chunkHash[1] = chunkHash[0];
            chunkHash[0] = temp;
        }

        private static byte[] CreateResult(uint[] hash)
        {
            var result = new byte[20];
            for (var i = 0; i < 5; i++)
            {
                var wordBytes = HashOps.UIntToBytes(hash[i]);
                Array.Reverse(wordBytes);
                wordBytes.CopyTo(result, 4 * i);
            }
            return result;
        }

        public static byte[] ComputeHash(byte[] message)
        {
            var hash = new uint[]
            {
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0
            };
            var paddedMessage = PadMessage(message);
            var chunks = paddedMessage.Length / 64;
            var chunkData = new byte[64];
            var words = new uint[80];
            for (var i = 0; i < chunks; i++)
            {
                Array.Copy(paddedMessage, i * 64, chunkData, 0, 64);
                PrepareWords(chunkData, words);
                var chunkHash = new uint[5];
                hash.CopyTo(chunkHash, 0);
                for (var j = 0; j < 80; j++)
                {
                    CalcState(chunkHash, words, j);
                }
                for (var j = 0; j < 5; j++)
                {
                    hash[j] += chunkHash[j];
                }
            }
            return CreateResult(hash);
        }
    }
}
