using System;
using Lab1.Interfaces;

namespace Lab1.Core;

public sealed class FeistelNetwork
{
    private readonly IKeyExpander _keyExpander;
    private readonly IRoundTransform _roundTransform;

    public FeistelNetwork(IKeyExpander keyExpander, IRoundTransform roundTransform)
    {
        _keyExpander = keyExpander ?? throw new ArgumentNullException(nameof(keyExpander));
        _roundTransform = roundTransform ?? throw new ArgumentNullException(nameof(roundTransform));
    }


    public byte[] Encrypt(byte[] block, byte[] key) => EncryptWithRoundKeys(block, _keyExpander.ExpandKey(key));

    public byte[] Decrypt(byte[] block, byte[] key) => DecryptWithRoundKeys(block, _keyExpander.ExpandKey(key));

    public byte[] EncryptWithRoundKeys(byte[] block, byte[][] roundKeys) => Transform(block, roundKeys, reverseKeys: false);

    public byte[] DecryptWithRoundKeys(byte[] block, byte[][] roundKeys) => Transform(block, roundKeys, reverseKeys: true);


    private byte[] Transform(byte[] block, byte[][] roundKeys, bool reverseKeys)
    {
        Validate(block, roundKeys);

        int halfSize = block.Length / 2;
        byte[] left = new byte[halfSize];
        byte[] right = new byte[halfSize];
        Array.Copy(block, 0, left, 0, halfSize);
        Array.Copy(block, halfSize, right, 0, halfSize);

        for (int round = 0; round < roundKeys.Length; round++)
        {
            byte[] roundKey = roundKeys[reverseKeys ? roundKeys.Length - 1 - round : round];
            byte[] transformed = _roundTransform.Transform(right, roundKey);
            
            if (transformed == null || transformed.Length != halfSize)
                throw new InvalidOperationException("The round transform must return exactly half a block.");

            byte[] nextRight = new byte[halfSize];
            for (int i = 0; i < halfSize; i++)
                nextRight[i] = (byte)(left[i] ^ transformed[i]);

            left = right;
            right = nextRight;
        }

        byte[] result = new byte[block.Length];
        Array.Copy(right, 0, result, 0, halfSize);
        Array.Copy(left, 0, result, halfSize, halfSize);
        return result;
    }

    private static void Validate(byte[] block, byte[][] roundKeys)
    {
        ArgumentNullException.ThrowIfNull(block);
        ArgumentNullException.ThrowIfNull(roundKeys);
        if (block.Length == 0 || (block.Length & 1) != 0)
            throw new ArgumentException("A Feistel block must have a positive even number of bytes.", nameof(block));

        if (roundKeys.Length == 0)
            throw new InvalidOperationException("The key expander must produce at least one round key.");
    }
}
