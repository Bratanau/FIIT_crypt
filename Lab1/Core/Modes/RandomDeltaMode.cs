using System;
using System.Security.Cryptography;
using Lab1.Interfaces;

namespace Lab1.Core.Modes;

public sealed class RandomDeltaMode : CipherModeBase
{
    private readonly byte[]? _configuredDelta;

    public RandomDeltaMode(byte[]? iv, params object[] extra) : base(iv, extra)
    {
        extra ??= Array.Empty<object>();
        if (extra.Length > 1 || (extra.Length == 1 && extra[0] is not byte[]))
            throw new ArgumentException("Random Delta accepts at most one byte[] delta parameter.", nameof(extra));
        _configuredDelta = extra.Length == 1 ? (byte[])((byte[])extra[0]).Clone() : null;
    }

    public override byte[] Encrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        ValidateInput(data, algorithm);
        byte[] counter = GetValidatedIv(algorithm.BlockSize);
        byte[] delta;
        if (_configuredDelta == null)
        {
            delta = RandomNumberGenerator.GetBytes(algorithm.BlockSize);
            delta[^1] |= 1;
        }
        else
        {
            delta = (byte[])_configuredDelta.Clone();
        }
        ValidateDelta(delta, algorithm.BlockSize);

        byte[] result = new byte[algorithm.BlockSize + data.Length];
        Array.Copy(delta, result, delta.Length);
        for (int offset = 0; offset < data.Length; offset += algorithm.BlockSize)
        {
            byte[] stream = algorithm.EncryptBlock(counter);
            int count = Math.Min(algorithm.BlockSize, data.Length - offset);
            for (int i = 0; i < count; i++)
                result[algorithm.BlockSize + offset + i] = (byte)(data[offset + i] ^ stream[i]);
            AddDelta(counter, delta);
        }
        return result;
    }

    public override byte[] Decrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        ValidateInput(data, algorithm);
        if (data.Length < algorithm.BlockSize)
            throw new ArgumentException("Random Delta ciphertext is missing its delta header.", nameof(data));
        byte[] counter = GetValidatedIv(algorithm.BlockSize);
        byte[] delta = new byte[algorithm.BlockSize];
        Array.Copy(data, delta, delta.Length);
        ValidateDelta(delta, algorithm.BlockSize);
        int payloadLength = data.Length - algorithm.BlockSize;
        byte[] result = new byte[payloadLength];
        for (int offset = 0; offset < payloadLength; offset += algorithm.BlockSize)
        {
            byte[] stream = algorithm.EncryptBlock(counter);
            int count = Math.Min(algorithm.BlockSize, payloadLength - offset);
            for (int i = 0; i < count; i++)
                result[offset + i] = (byte)(data[algorithm.BlockSize + offset + i] ^ stream[i]);
            AddDelta(counter, delta);
        }
        return result;
    }

    private static void ValidateDelta(byte[] delta, int blockSize)
    {
        if (delta.Length != blockSize)
            throw new ArgumentException($"The Random Delta value must be {blockSize} bytes long.");
        
        bool nonzero = false;
        foreach (byte value in delta)
            nonzero |= value != 0;
        if (!nonzero || (delta[^1] & 1) == 0)
            throw new ArgumentException("The Random Delta value must be nonzero and odd.");
    }

    private static void AddDelta(byte[] counter, byte[] delta)
    {
        int carry = 0;
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            int sum = counter[i] + delta[i] + carry;
            counter[i] = (byte)sum;
            carry = sum >> 8;
        }
    }
}
