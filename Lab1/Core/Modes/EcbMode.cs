using System;
using Lab1.Interfaces;

namespace Lab1.Core.Modes;

public sealed class EcbMode : CipherModeBase
{
    public EcbMode() : base(null) { }
    
    public override byte[] Encrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {

    }

    public override byte[] Decrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        
    }
}