using System;
using Lab1.BitUtils;
using Lab1.Core;
using Lab1.Interfaces;

namespace Lab1.Des;

public sealed class DesCipher : ISymmetricAlgorithm
{
    private readonly DesKeyExpander _keyExpander = new();
    private readonly FeistelNetwork _network;
    private byte[][]? _roundKeys;

    public DesCipher()
    {
        _network = new FeistelNetwork(_keyExpander, new DesRoundFunction());
    }

    public int BlockSize { get => 8; }

    public void SetKey(byte[] key)
    {
        Validate(key);
        _roundKeys = _keyExpander.ExpandKey(key);
    }

    public byte[] EncryptBlock(byte[] block) => TransformBlock(block, true);
    public byte[] DecryptBlock(byte[] block) => TransformBlock(block, false);

    private byte[] TransformBlock(byte[] block, bool encrypt)
    {
        Validate(block);

        byte[][] roundKeys = _roundKeys ?? throw new InvalidOperationException("SetKey must be called before using DES.");
        byte[] initial = BitPermutation.Permute(block, DesTables.IP, BitOrder.MsbFirst, 1);
        byte[] transformed = encrypt
            ? _network.EncryptWithRoundKeys(initial, roundKeys)
            : _network.DecryptWithRoundKeys(initial, roundKeys);
        return BitPermutation.Permute(transformed, DesTables.FP, BitOrder.MsbFirst, 1);
    }

    private void Validate(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != BlockSize)
            throw new ArgumentException("A DES must contain exactly 8 bytes.", nameof(block));
    } 
}