using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
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

    public SymmetricCipherContext(ISymmetricAlgorithm algorithm, byte[] key, CipherMode cipherMode, PaddingMode paddingMode, byte[]? iv = null, params object[] extra)
    {
        _algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
        ArgumentNullException.ThrowIfNull(key);
        if (_algorithm.BlockSize <= 0)
            throw new ArgumentException("The algorithm block size must be positive.", nameof(algorithm));

        _mode = cipherMode;
        _padding = paddingMode;
        _iv = iv == null ? null : (byte[])iv.Clone();
        _extra = extra ?? Array.Empty<object>();
        _modeProcessor = CipherModeFactory.Create(_mode, _iv, _extra);
        _algorithm.SetKey(key);
    }

    public byte[] Encrypt(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        byte[] padded = Padding.Add(data, _algorithm.BlockSize, _padding);
        return _modeProcessor.Encrypt(padded, _algorithm);
    }

    public byte[] Decrypt(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        byte[] processed = _modeProcessor.Decrypt(data, _algorithm);
        return Padding.Remove(processed, _algorithm.BlockSize, _padding);
    }
    

    public void Encrypt(byte[] data, out byte[] result) => result = Encrypt(data);
    public void Decrypt(byte[] data, out byte[] result) => result = Decrypt(data);

    public void Encrypt(string inputPath, string outputPath) => File.WriteAllBytes(outputPath, Encrypt(File.ReadAllBytes(inputPath)));
    public void Decrypt(string inputPath, string outputPath) => File.WriteAllBytes(outputPath, Decrypt(File.ReadAllBytes(inputPath)));


    public Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        byte[] input = (byte[])data.Clone();
        return Task.Run(() => Encrypt(input), cancellationToken);
    }

    public Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        byte[] input = (byte[])data.Clone();
        return Task.Run(() => Decrypt(input), cancellationToken);
    }

    public async Task EncryptAsync(string inputPath, string outputPath, CancellationToken cancellationToken = default)
    {
        byte[] input = await File.ReadAllBytesAsync(inputPath, cancellationToken).ConfigureAwait(false);
        byte[] encrypted = await EncryptAsync(input, cancellationToken).ConfigureAwait(false);
        await File.WriteAllBytesAsync(outputPath, encrypted, cancellationToken).ConfigureAwait(false);
    }

    public async Task DecryptAsync(string inputPath, string outputPath, CancellationToken cancellationToken = default)
    {
        byte[] input = await File.ReadAllBytesAsync(inputPath, cancellationToken).ConfigureAwait(false);
        byte[] decrypted = await DecryptAsync(input, cancellationToken).ConfigureAwait(false);
        await File.WriteAllBytesAsync(outputPath, decrypted, cancellationToken).ConfigureAwait(false);
    }
}