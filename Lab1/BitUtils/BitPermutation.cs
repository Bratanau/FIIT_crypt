using System;

namespace Lab1.BitUtils
{
    public static class BitPermutation
    {
        public static byte[] Permute(byte[] input, int[] pBlock, BitOrder order, int firstBitIndex)
        {
            ArgumentNullException.ThrowIfNull(input);
            ArgumentNullException.ThrowIfNull(pBlock);
            if (firstBitIndex != 0 && firstBitIndex != 1)
                throw new ArgumentOutOfRangeException(nameof(firstBitIndex), "The first bit index must be 0 or 1.");
            if (pBlock.Length == 0)
                return Array.Empty<byte>();

            int outBits = pBlock.Length;
            byte[] output = new byte[(outBits + 7) / 8];

            for (int i = 0; i < outBits; i++)
            {
                int srcBitIndex = pBlock[i] - firstBitIndex;
                bool bit = GetBit(input, srcBitIndex, order);
                SetBit(output, i, bit, order);
            }
            return output;
        }

        public static bool GetBit(byte[] data, int bitIndex, BitOrder order)
        {
            Validate(data, bitIndex, order);

            int byteIndex = bitIndex / 8;
            int bitInByte = bitIndex % 8;

            if (order == BitOrder.LsbFirst) 
                return ((data[byteIndex] >> bitInByte) & 1) != 0;
            return ((data[byteIndex] >> (7 - bitInByte)) & 1) != 0;
        }

        public static void SetBit(byte[] data, int bitIndex, bool value, BitOrder order)
        {
            Validate(data, bitIndex, order);

            int byteIndex = bitIndex / 8;
            int bitInByte = bitIndex % 8;

            int mask = (order == BitOrder.LsbFirst)
                ? 1 << bitInByte
                : 1 << (7 - bitInByte);

            if (value)
                data[byteIndex] = (byte)(data[byteIndex] | mask);
            else
                data[byteIndex] = (byte)(data[byteIndex] & ~mask);
        }

        private static void Validate(byte[] data, int bitIndex, BitOrder order)
        {
            ArgumentNullException.ThrowIfNull(data);

            if (order != BitOrder.LsbFirst && order != BitOrder.MsbFirst)
                throw new ArgumentOutOfRangeException(nameof(order));

            if (bitIndex < 0 || bitIndex >= data.Length * 8)
                throw new ArgumentOutOfRangeException(nameof(bitIndex));
        }
    }
}