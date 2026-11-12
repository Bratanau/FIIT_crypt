using System;
using Lab1.Core;
using Lab1.Interfaces;

namespace Lab1.Deal;

public sealed class DealCipher : ISymmetricAlgorithm
{
    private readonly DealKeyExpander _keyExpander = new();
    private readonly FeistelNetwork _network;
    private byte[][]? _roundKeys;

    public DealCipher()
    {
        _network = new FeistelNetwork(_keyExpander, new DesAsDealRoundFunction());
    }

    public int BlockSize { get => 16; }

    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            throw new ArgumentException("DEAL keys must contain 16, 24, or 32 bytes.", nameof(key));
        _roundKeys = _keyExpander.ExpandKey(key);
    }

    public byte[] EncryptBlock(byte[] block) => TransformBlock(block, true);
    public byte[] DecryptBlock(byte[] block) => TransformBlock(block, false);

    private byte[] TransformBlock(byte[] block, bool encrypt)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != BlockSize)
            throw new ArgumentException("A DEAL block must contain exactly 16 bytes.", nameof(block));
        byte[][] roundKeys = _roundKeys ?? throw new InvalidOperationException("SetKey must be called before using DEAL.");
        return encrypt
            ? _network.EncryptWithRoundKeys(block, roundKeys)
            : _network.DecryptWithRoundKeys(block, roundKeys);
    }
}