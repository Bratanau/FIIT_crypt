using System;
using Lab1.Interfaces;

namespace Lab1.Core.Modes;

public sealed class EcbMode : CipherModeBase
{
    public EcbMode() : base(null) { }
    
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
        
        byte[] result = new byte[data.Length];
        for (int offset = 0; offset < data.Length; offset += algorithm.BlockSize)
        {
            byte[] block = new byte[algorithm.BlockSize];
            Array.Copy(data, offset, block, 0, block.Length);
            byte[] transformed = encrypt ? algorithm.EncryptBlock(block) : algorithm.DecryptBlock(block);

            if (transformed.Length != block.Length)
                throw new InvalidOperationException("The algorithm returned a block of an unexpected size.");
                
            Array.Copy(transformed, 0, result, offset, transformed.Length);
        }
        return result;
    }
}