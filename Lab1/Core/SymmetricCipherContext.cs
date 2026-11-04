using System;
using System.IO;
using Lab1.Core.Modes;
using Lab1.Interfaces;

namespace Lab1.Core;

public class SymmetricCipherContext
{
    private readonly ISymmetricAlgorithm _algorithm;
    private readonly CipherMode _mode;
    private readonly PaddingMode _padding;
    private readonly ICipherModeProcessor _modeProcessor;
    private readonly byte[]? _iv;
    private readonly object[] _extra;

    public SymmetricCipherContext(
        ISymmetricAlgorithm algorithm,
        byte[] key,
        CipherMode cipherMode,
        PaddingMode paddingMode,
        byte[]? iv = null,
        params object[] extra)
    {
        _algorithm = algorithm;
        _mode = cipherMode;
        _padding = paddingMode;
        _iv = iv;
        _extra = extra ?? Array.Empty<object>();

        _modeProcessor = CipherModeFactory.Create(_mode, _iv, _extra);

        _algorithm.SetKey(key);
    }

    public byte[] Encrypt(byte[] data)
    {
        byte[] padded = Padding.Add(data, _algorithm.BlockSize, _padding);
        return _modeProcessor.Encrypt(padded, _algorithm);
    }

    public byte[] Decrypt(byte[] data)
    {
        byte[] processed = _modeProcessor.Decrypt(data, _algorithm);
        return Padding.Remove(processed, _algorithm.BlockSize, _padding);
    }

    public void Encrypt(byte[] data, out byte[] result) => result = Encrypt(data);
    public void Decrypt(byte[] data, out byte[] result) => result = Decrypt(data);

    public void Encrypt(string inputPath, string outputPath) 
        => File.WriteAllBytes(outputPath, Encrypt(File.ReadAllBytes(inputPath)));

    public void Decrypt(string inputPath, string outputPath) 
        => File.WriteAllBytes(outputPath, Decrypt(File.ReadAllBytes(inputPath)));

}