using System;
namespace Lab1.BitUtils
{
    public static class BitPermutation
    {
        public static byte[] Permute(
            byte[] input,
            int[] pBlock,
            BitOrder order,
            int firstBitIndex
        )
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (pBlock == null) throw new ArgumentNullException(nameof(pBlock));
            if (firstBitIndex != 0 && firstBitIndex != 1) throw new ArgumentException("0/1");

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
            if (bitIndex < 0 || bitIndex >= data.Length * 8)
                throw new ArgumentOutOfRangeException(nameof(bitIndex));

            int byteIndex = bitIndex / 8;
            int bitInByte = bitIndex % 8;

            if (order == BitOrder.LsbFirst) 
                return ((data[byteIndex] >> bitInByte) & 1) != 0;
            else
                return ((data[byteIndex] >> (7 - bitInByte)) & 1) != 0;

        }

        public static bool SetBit(byte[] data, int bitIndex, bool value, BitOrder order)
        {
            if (bitIndex < 0 || bitIndex >= data.Length * 8)
                throw new ArgumentOutOfRangeException(nameof(bitIndex));

            int byteIndex = bitIndex / 8;
            int bitInByte = bitIndex % 8;

            int mask = (order == BitOrder.LsbFirst)
                ? 1 << bitInByte
                : 1 << (7 - bitinByte);

            if (value)
                data[byteIndex] = data[buteIndex] | (byte)mask;
            else
                data[byteIndex] = data[byteIndex] & (byte)~mask;
        }
    }
}