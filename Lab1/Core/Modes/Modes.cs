using System;
using Lab1.Interfaces;

namespace Lab1.Core.Modes;

public interface ICipherModeProcessor
{
    byte[] Encrypt(byte[] data, ISymmetricAlgorithm algorithm);
    byte[] Decrypt(byte[] data, ISymmetricAlgorithm algorithm);
}

public abstract class CipherModeBase : ICipherModeProcessor
{
    protected readonly byte[]? _iv;
    protected readonly object[] _extra;

    protected CipherModeBase(byte[]? iv, params object[] extra)
    {
        _iv = iv;
        _extra = extra ?? Array.Empty<object>();
    }

    public abstract byte[] Encrypt(byte[] data, ISymmetricAlgorithm algorithm);
    public abstract byte[] Decrypt(byte[] data, ISymmetricAlgorithm algorithm);

    protected byte[] TakeBlock(byte[] data, int offset, int blockSize)
    {
        var block = new byte[blockSize];
        int len = Math.Min(blockSize, data.Length - offset);
        Array.Copy(data, offset, block, 0, len);
        return block;
    }

    public static byte[] Xor(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) throw new ArgumentException("Lengths must be equal");

        byte[] result = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
            result[i] = (byte)(a[i] ^ b[i]);
        return result;
    }

    protected static void IncrementCounter(byte[] counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
                break;
        }
    }

    protected byte[] GetIvOrThrow()
    {
        if (_iv == null) throw new InvalidCastException("IV is required for this mode");
        return _iv;
    }
}