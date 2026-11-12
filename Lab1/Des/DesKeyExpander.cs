using System;
using Lab1.BitUtils;
using Lab1.Interfaces;

namespace Lab1.Des;

public sealed class DesKeyExpander : IKeyExpander
{
    public byte[][] ExpandKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 8)
            throw new ArgumentException("A DES key must contain exactly 8 bytes.", nameof(key));

        byte[] selected = BitPermutation.Permute(key, DesTables.PC1, BitOrder.MsbFirst, 1);
        byte[] left = new byte[4];
        byte[] right = new byte[4];
        for (int bit = 0; bit < 28; bit++)
        {
            BitPermutation.SetBit(left, bit, BitPermutation.GetBit(selected, bit, BitOrder.MsbFirst), BitOrder.MsbFirst);
            BitPermutation.SetBit(right, bit, BitPermutation.GetBit(selected, bit + 28, BitOrder.MsbFirst), BitOrder.MsbFirst);
        }

        byte[][] keys = new byte[16][];
        for (int round = 0; round < keys.Length; round++)
        {
            left = Rotate28(left, DesTables.KeyRotations[round]);
            right = Rotate28(right, DesTables.KeyRotations[round]);
            
            byte[] combined = new byte[7];
            for (int bit = 0; bit < 28; bit++)
            {
                BitPermutation.SetBit(combined, bit, BitPermutation.GetBit(left, bit, BitOrder.MsbFirst), BitOrder.MsbFirst);
                BitPermutation.SetBit(combined, bit + 28, BitPermutation.GetBit(right, bit, BitOrder.MsbFirst), BitOrder.MsbFirst);
            }
            keys[round] = BitPermutation.Permute(combined, DesTables.PC2, BitOrder.MsbFirst, 1);
        }
        return keys;
    }

    private static byte[] Rotate28(byte[] value, int count)
    {
        byte[] result = new byte[4];
        for (int bit = 0; bit < 28; bit++)
            BitPermutation.SetBit(result, bit,
                BitPermutation.GetBit(value, (bit + count) % 28, BitOrder.MsbFirst),
                BitOrder.MsbFirst);
        return result;
    }
}