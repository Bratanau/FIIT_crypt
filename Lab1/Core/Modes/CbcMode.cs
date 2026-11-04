using System;
using Lab1.Interfaces;

namespace Lab1.Core.Modes;

public sealed class CbcMode : CipherModeBase
{
    public CbcMode(byte[] iv) : base(iv) { }

    public override byte[] Encrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        
    }

    public override byte[] Decrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        
    }
}