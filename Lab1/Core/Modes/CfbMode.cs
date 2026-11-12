using System;
using Lab1.Interfaces;

namespace Lab1.Core.Modes;

public sealed class CfbMode : CipherModeBase
{
    public CfbMode(byte[]? iv) : base(iv) { }

    public override byte[] Encrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        return Transform(data, algorithm, encrypt: true);
    }

    public override byte[] Decrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        return Transform(data, algorithm, encrypt: false);
    }

    private byte[] Transform(byte[] data, ISymmetricAlgorithm algorithm, bool encrypt)
    {
        ValidateInput(data, algorithm);
        byte[] feedback = GetValidatedIv(algorithm.BlockSize);
        byte[] result = new byte[data.Length];
        for (int offset = 0; offset < data.Length; offset += algorithm.BlockSize)
        {
            byte[] stream = algorithm.EncryptBlock(feedback);
            int count = Math.Min(algorithm.BlockSize, data.Length - offset);
            byte[] cipherSegment = new byte[count];
            for (int i = 0; i < count; i++)
            {
                byte output = (byte)(data[offset + i] ^ stream[i]);
                result[offset + i] = output;
                cipherSegment[i] = encrypt ? output : data[offset + i];
            }

            if (count == algorithm.BlockSize)
                feedback = cipherSegment;
        }
        return result;
    }
}