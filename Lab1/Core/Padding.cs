using System;
using RandomNumberGenerator = System.Security.Cryptography.RandomNumberGenerator;
using Lab1.Interfaces;

namespace Lab1.Core;

public static class Padding
{
    public static byte[] Add(byte[] data, int blockSize, PaddingMode mode)
    {
        Validate(data, blockSize, mode);

        int paddingLength = mode == PaddingMode.Zeros
            ? (blockSize - data.Length % blockSize) % blockSize
            : blockSize - data.Length % blockSize;

        byte[] result = new byte[data.Length + paddingLength];
        Array.Copy(data, result, data.Length);

        if (paddingLength == 0)
            return result;

        switch (mode)
        {
            case PaddingMode.Zeros:
                break;
            case PaddingMode.ANSIX923:
                result[^1] = (byte)paddingLength;
                break;
            case PaddingMode.PKCS7:
                Array.Fill(result, (byte)paddingLength, data.Length, paddingLength);
                break;
            case PaddingMode.ISO10126:
                if (paddingLength > 1)
                    RandomNumberGenerator.Fill(result.AsSpan(data.Length, paddingLength - 1));
                result[^1] = (byte)paddingLength;
                break;
        }
        return result;
    }

    public static byte[] Remove(byte[] data, int blockSize, PaddingMode mode)
    {
        Validate(data, blockSize, mode);

        if (data.Length == 0)
            return Array.Empty<byte>();
        if (data.Length % blockSize != 0)
            throw new FormatException("Padded data length must be a multiple of the block size.");

        switch (mode)
        {
            case PaddingMode.Zeros:
            {
                int length = data.Length;
                while (length > 0 && data[length - 1] == 0)
                    length--;

                byte[] unpadded = new byte[length];
                Array.Copy(data, unpadded, length);
                return unpadded;
            }
            case PaddingMode.ANSIX923:
            case PaddingMode.PKCS7:
            case PaddingMode.ISO10126:
            {
                int paddingLength = data[^1];
                if (paddingLength == 0 || paddingLength > blockSize || paddingLength > data.Length)
                    throw new FormatException("The padding length is invalid.");

                switch (mode)
                {
                    case PaddingMode.PKCS7:
                        for (int i = data.Length - paddingLength; i < data.Length; i++)
                            if (data[i] != paddingLength)
                                throw new FormatException("PKCS7 padding is invalid.");
                        break;
                    case PaddingMode.ANSIX923:
                        for (int i = data.Length - paddingLength; i < data.Length - 1; i++)
                            if (data[i] != 0)
                                throw new FormatException("ANSI X.923 padding is invalid.");
                        break;
                }

                byte[] unpadded = new byte[data.Length - paddingLength];
                Array.Copy(data, unpadded, unpadded.Length);
                return unpadded;
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    private static void ValidateBlockSize(int blockSize)
    {
        if (blockSize <= 0 || blockSize > byte.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(blockSize), "Block size must be from 1 through 255 bytes.");
    }

    private static void ValidateMode(PaddingMode mode)
    {
        if (mode != PaddingMode.Zeros && mode != PaddingMode.ANSIX923
            && mode != PaddingMode.PKCS7 && mode != PaddingMode.ISO10126)
            throw new ArgumentOutOfRangeException(nameof(mode));
    }

    private static void Validate(byte[] data, int blockSize, PaddingMode mode)
    {
        ArgumentNullException.ThrowIfNull(data);
        ValidateBlockSize(blockSize);
        ValidateMode(mode);
    }
}