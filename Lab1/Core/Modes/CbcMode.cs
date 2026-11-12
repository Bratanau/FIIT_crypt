using System;
using Lab1.Interfaces;

namespace Lab1.Core.Modes;

public sealed class CbcMode : CipherModeBase
{
    public CbcMode(byte[]? iv) : base(iv) { }

    public override byte[] Encrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        return Transform(data, algorithm, true);
    }

    public override byte[] Decrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        return Transform(data, algorithm, false);
    }

    private byte[] Transform(byte[] data, ISymmetricAlgorithm algorithm, bool encrypt)
    {
        ValidateInput(data, algorithm);
        ValidateBlockAligned(data, algorithm.BlockSize);
        
        byte[] chain = GetValidatedIv(algorithm.BlockSize);
        byte[] result = new byte[data.Length];
        for (int offset = 0; offset < data.Length; offset += algorithm.BlockSize)
        {
            byte[] block = TakeBlock(data, offset, algorithm.BlockSize);
            byte[] transformed = encrypt ? algorithm.EncryptBlock(Xor(block, chain)) : Xor(algorithm.DecryptBlock(block), chain);
            if (transformed.Length != algorithm.BlockSize)
                throw new InvalidOperationException("The algorithm returned a block of an unexpected size.");
            Array.Copy(transformed, 0, result, offset, transformed.Length);
            chain = encrypt ? transformed : block;
        }
        return result;
    }
}
