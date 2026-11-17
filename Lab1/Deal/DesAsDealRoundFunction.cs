using System;
using Lab1.Des;
using Lab1.Interfaces;

namespace Lab1.Deal;

public sealed class DesAsDealRoundFunction : IRoundTransform
{
    public byte[] Transform(byte[] blockPart, byte[] roundKey)
    {
        Validate(blockPart, roundKey);

        var des = new DesCipher();
        des.SetKey(roundKey);
        return des.EncryptBlock(blockPart);
    }

    private void Validate(byte[] blockPart, byte[] roundKey)
    {
        ArgumentNullException.ThrowIfNull(blockPart);
        ArgumentNullException.ThrowIfNull(roundKey);
        if (blockPart.Length != 4)
            throw new ArgumentException("A DEAL round input must contain 4 bytes.", nameof(blockPart));
        if (roundKey.Length != 6)
            throw new ArgumentException("A DEAL round key must contain 6 bytes.", nameof(roundKey));
    }
}