using System;
using Lab1.Des;
using Lab1.Interfaces;

namespace Lab1.Deal;

public sealed class DesAsDealRoundFunction : IRoundTransform
{
    public byte[] Transform(byte[] blockPart, byte[] roundKey)
    {
        DesRoundFunction.Validate(blockPart, roundKey);

        var des = new DesCipher();
        des.SetKey(roundKey);
        return des.EncryptBlock(blockPart);
    }
}