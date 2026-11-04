using System;
using Lab1.Interfaces;

namespace Lab1.Core.Modes
{
    public class CipherModeFactory
    {
        public static ICipherModeProcessor Create(
            CipherMode mode,
            byte[]? iv,
            object[] extra)
        {
            return mode switch
            {
                CipherMode.ECB => new EcbMode(),
                CipherMode.CBC => new CbcMode(iv!),
                CipherMode.CFB => new CfbMode(iv!),
                CipherMode.OFB => new OfbMode(iv!),
                CipherMode.CTR => new CtrMode(iv!),
                CipherMode.PCBC => new PcbcMode(iv!),
                CipherMode.RandomDelta => new RandomDeltaMode(iv!),
                _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, null)
            };
        }
    }
}
