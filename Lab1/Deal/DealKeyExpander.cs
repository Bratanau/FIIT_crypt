using System;
using Lab1.Des;
using Lab1.Interfaces;

namespace Lab1.Deal;

public sealed class DealKeyExpander : IKeyExpander
{
    public byte[][] ExpandKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            throw new ArgumentException("DEAL keys must contain 16, 24, or 32 bytes.", nameof(key));

        int rounds = key.Length == 32 ? 8 : 6;
        int keyParts = key.Length / 8;
        byte[][] roundKeys = new byte[rounds][];
        var des = new DesCipher();
        byte[] seed = new byte[8];

        for (int round = 0; round < rounds; round++)
        {
            byte[] desKey = new byte[8];
            Array.Copy(key, (round % keyParts) * 8, desKey, 0, 8);
            seed[7] ^= (byte)(round + 1);
            des.SetKey(desKey);
            seed = des.EncryptBlock(seed);
            roundKeys[round] = (byte[])seed.Clone();
        }
        return roundKeys;
    }
}
