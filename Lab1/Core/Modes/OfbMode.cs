using System;
using Lab1.Interfaces;

namespace Lab1.Core.Modes;

public sealed class OfbMode : CipherModeBase
{
    public OfbMode(byte[]? iv) : base(iv) { }

    public override byte[] Encrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        return Transform(data, algorithm);
    }

    public override byte[] Decrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        return Transform(data, algorithm);
    }

    private byte[] Transform(byte[] data, ISymmetricAlgorithm algorithm)
    {
        ValidateInput(data, algorithm);
        byte[] state = GetValidatedIv(algorithm.BlockSize);
        byte[] result = new byte[data.Length];
        for (int offset = 0; offset < data.Length; offset += algorithm.BlockSize)
        {
            state = algorithm.EncryptBlock(state);
            int count = Math.Min(algorithm.BlockSize, data.Length - offset);
            for (int i = 0; i < count; i++)
                result[offset + i] = (byte)(data[offset + i] ^ state[i]);
        }
        return result;
    }
}