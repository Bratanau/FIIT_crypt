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
            extra ??= Array.Empty<object>();
            return mode switch
            {
                CipherMode.ECB => new EcbMode(),
                CipherMode.CBC => new CbcMode(RequireIv(iv, mode)),
                CipherMode.CFB => new CfbMode(RequireIv(iv, mode)),
                CipherMode.OFB => new OfbMode(RequireIv(iv, mode)),
                CipherMode.CTR => new CtrMode(RequireIv(iv, mode)),
                CipherMode.PCBC => new PcbcMode(RequireIv(iv, mode)),
                CipherMode.RandomDelta => new RandomDeltaMode(RequireIv(iv, mode), extra),
                _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, null)
            };
        }

        private static byte[] RequireIv(byte[]? iv, CipherMode mode)
            => iv ?? throw new ArgumentException($"Mode {mode} requires an initialization vector.", nameof(iv));
    }
}
