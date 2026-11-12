using System;
using Lab1.BitUtils;
using Lab1.Interfaces;

namespace Lab1.Des;

public sealed class DesRoundFunction : IRoundTransform
{
    public byte[] Transform(byte[] blockPart, byte[] roundKey)
    {
        Validate(blockPart, roundKey);

        byte[] expanded = BitPermutation.Permute(blockPart, DesTables.E, BitOrder.MsbFirst, 1);
        for (int i = 0; i < expanded.Length; i++)
            expanded[i] ^= roundKey[i];

        byte[] substituted = new byte[4];
        for (int box = 0; box < 8; box++)
        {
            int offset = box * 6;
            int row = (BitPermutation.GetBit(expanded, offset, BitOrder.MsbFirst) ? 2 : 0)
                    | (BitPermutation.GetBit(expanded, offset + 5, BitOrder.MsbFirst) ? 1 : 0);
                    
            int column = 0;
            for (int bit = 1; bit <= 4; bit++)
                column = (column << 1) | (BitPermutation.GetBit(expanded, offset + bit, BitOrder.MsbFirst) ? 1 : 0);

            int value = DesTables.SBoxes[box][row * 16 + column];
            for (int bit = 0; bit < 4; bit++)
                BitPermutation.SetBit(substituted, box * 4 + bit, ((value >> (3 - bit)) & 1) != 0, BitOrder.MsbFirst);
        }
        return BitPermutation.Permute(substituted, DesTables.P, BitOrder.MsbFirst, 1);
    }

    public static void Validate(byte[] blockPart, byte[] roundKey) // used in DesAsDealRoundFunction
    {
        ArgumentNullException.ThrowIfNull(blockPart);
        ArgumentNullException.ThrowIfNull(roundKey);
        if (blockPart.Length != 4)
            throw new ArgumentException("A DES round input must contain 4 bytes.", nameof(blockPart));
        if (roundKey.Length != 6)
            throw new ArgumentException("A DES round key must contain 6 bytes.", nameof(roundKey));
    }
}