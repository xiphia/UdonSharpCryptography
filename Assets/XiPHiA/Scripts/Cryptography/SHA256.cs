using System;
using XiPHiA.Scripts.Utility;

namespace XiPHiA.Scripts.Cryptography
{
    public static class SHA256
    {
        private static void PrepareWords(byte[] chunk, uint[] words)
        {
            for (var i = 0; i < 16; i++)
            {
                words[i] = chunk.GetUInt(i * 4);
            }
            for (var i = 16; i < 64; i++)
            {
                var s0 = words[i - 15].RightRotate(7) ^ words[i - 15].RightRotate(18) ^ words[i - 15] >> 3;
                var s1 = words[i - 2].RightRotate(17) ^ words[i - 2].RightRotate(19) ^ words[i - 2] >> 10;
                words[i] = words[i - 16] + s0 + words[i - 7] + s1;
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
            ((long)messageLength * 8).ToByteArray(true).CopyTo(paddedMessage, paddedLength - 8);
            return paddedMessage;
        }

        private static void CalcState(uint[] chunkHash, uint[] words, int round)
        {
            var k = new uint[]
            {
                0x428A2F98,
                0x71374491,
                0xB5C0FBCF,
                0xE9B5DBA5,
                0x3956C25B,
                0x59F111F1,
                0x923F82A4,
                0xAB1C5ED5,
                0xD807AA98,
                0x12835B01,
                0x243185BE,
                0x550C7DC3,
                0x72BE5D74,
                0x80DEB1FE,
                0x9BDC06A7,
                0xC19BF174,
                0xE49B69C1,
                0xEFBE4786,
                0x0FC19DC6,
                0x240CA1CC,
                0x2DE92C6F,
                0x4A7484AA,
                0x5CB0A9DC,
                0x76F988DA,
                0x983E5152,
                0xA831C66D,
                0xB00327C8,
                0xBF597FC7,
                0xC6E00BF3,
                0xD5A79147,
                0x06CA6351,
                0x14292967,
                0x27B70A85,
                0x2E1B2138,
                0x4D2C6DFC,
                0x53380D13,
                0x650A7354,
                0x766A0ABB,
                0x81C2C92E,
                0x92722C85,
                0xA2BFE8A1,
                0xA81A664B,
                0xC24B8B70,
                0xC76C51A3,
                0xD192E819,
                0xD6990624,
                0xF40E3585,
                0x106AA070,
                0x19A4C116,
                0x1E376C08,
                0x2748774C,
                0x34B0BCB5,
                0x391C0CB3,
                0x4ED8AA4A,
                0x5B9CCA4F,
                0x682E6FF3,
                0x748F82EE,
                0x78A5636F,
                0x84C87814,
                0x8CC70208,
                0x90BEFFFA,
                0xA4506CEB,
                0xBEF9A3F7,
                0xC67178F2
            };
            var s0 = chunkHash[0].RightRotate(2) ^ chunkHash[0].RightRotate(13) ^ chunkHash[0].RightRotate(22);
            var s1 = chunkHash[4].RightRotate(6) ^ chunkHash[4].RightRotate(11) ^ chunkHash[4].RightRotate(25);
            var ch = chunkHash[4] & chunkHash[5] ^ (~chunkHash[4] & chunkHash[6]);
            var maj = chunkHash[0] & chunkHash[1] ^ (chunkHash[0] & chunkHash[2]) ^ (chunkHash[1] & chunkHash[2]);
            var temp1 = chunkHash[7] + s1 + ch + k[round] + words[round];
            var temp2 = s0 + maj;
            chunkHash[7] = chunkHash[6];
            chunkHash[6] = chunkHash[5];
            chunkHash[5] = chunkHash[4];
            chunkHash[4] = chunkHash[3] + temp1;
            chunkHash[3] = chunkHash[2];
            chunkHash[2] = chunkHash[1];
            chunkHash[1] = chunkHash[0];
            chunkHash[0] = temp1 + temp2;
        }

        private static byte[] CreateResult(uint[] hash)
        {
            var result = new byte[32];
            for (var i = 0; i < 8; i++)
            {
                hash[i].ToByteArray(true).CopyTo(result, 4 * i);
            }
            return result;
        }

        public static byte[] ComputeHash(byte[] message)
        {
            var hash = new uint[]
            {
                0x6A09E667,
                0xBB67AE85,
                0x3C6EF372,
                0xA54FF53A,
                0x510E527F,
                0x9B05688C,
                0x1F83D9AB,
                0x5BE0CD19
            };
            var paddedMessage = PadMessage(message);
            var chunks = paddedMessage.Length / 64;
            var chunkData = new byte[64];
            var words = new uint[64];
            for (var i = 0; i < chunks; i++)
            {
                Array.Copy(paddedMessage, i * 64, chunkData, 0, 64);
                PrepareWords(chunkData, words);
                var chunkHash = new uint[8];
                hash.CopyTo(chunkHash, 0);
                for (var j = 0; j < 64; j++)
                {
                    CalcState(chunkHash, words, j);
                }
                for (var j = 0; j < 8; j++)
                {
                    hash[j] += chunkHash[j];
                }
            }
            return CreateResult(hash);
        }
    }
}
