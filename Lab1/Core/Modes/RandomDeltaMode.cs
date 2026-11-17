using System;
using Lab1.Interfaces;

namespace Lab1.Core.Modes;

public sealed class RandomDeltaMode : CipherModeBase
{
    private static readonly Random _rng = new Random();

    public RandomDeltaMode(byte[]? iv) : base(iv) { }

    public override byte[] Encrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        return Transform(data, algorithm, encrypt: true);
    }

    public override byte[] Decrypt(byte[] data, ISymmetricAlgorithm algorithm)
    {
        return Transform(data, algorithm, encrypt: false);
    }

    private byte[] Transform(byte[] data, ISymmetricAlgorithm algorithm, bool encrypt)
{
    ValidateInput(data, algorithm);
    
    byte[] counter = GetValidatedIv(algorithm.BlockSize);
    byte[] result;
    int _delta;

    if (encrypt)
    {
        _delta = RandomPrime(100);
        result = new byte[data.Length + 4];
        Array.Copy(BitConverter.GetBytes(_delta), result, 4); 
    }
    else
    {
        if (data.Length < 4)
            throw new InvalidOperationException("The data is too short to contain a delta value.");

        _delta = BitConverter.ToInt32(data, 0);
        result = new byte[data.Length - 4];
    }

    int dataOffset = encrypt ? 0 : 4;      
    int resOffset = encrypt ? 4 : 0; 
    int dataLen = encrypt ? data.Length : data.Length - 4;

    for (int offset = 0; offset < dataLen; offset += algorithm.BlockSize)
    {
        byte[] stream = algorithm.EncryptBlock(counter);
        int count = Math.Min(algorithm.BlockSize, dataLen - offset);
        
        for (int i = 0; i < count; i++)
        {
            result[resOffset + offset + i] = (byte)(data[dataOffset + offset + i] ^ stream[i]);
        }
        AddIntToCounter(counter, _delta);
    }
    return result;
}

    private void AddIntToCounter(byte[] counter, int delta)
    {
        long counterValue = 0;
        for (int i = 0; i < counter.Length; i++)
        {
            counterValue = (counterValue << 8) + counter[i];
        }

        counterValue += delta;

        for (int i = counter.Length - 1; i >= 0; i--)
        {
            counter[i] = (byte)(counterValue & 0xFF);
            counterValue >>= 8;
        }
    }

    private int RandomPrime(int max)
    {
        if (max < 2)
            throw new ArgumentException("Maximum value must be greater than 2");
        if (max == 2)
            return 2;
        while (true)
        {
            int candidate = _rng.Next(2, max);
            if (IsPrime(candidate))
                return candidate;
        }
    }

    private bool IsPrime(int n)
    {
        if (n < 2) return false;
        if (n == 2) return true;
        if (n % 2 == 0) return false;

        for (int i = 3; i * i <= n; i += 2)
        {
            if (n % i == 0) return false;
        }
        return true;
    }
}
