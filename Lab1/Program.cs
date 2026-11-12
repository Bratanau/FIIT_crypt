using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Lab1.Core;
using Lab1.Des;
using Lab1.Deal;
using Lab1.Interfaces;

internal static class Program
{
    private static async Task Main()
    {
        VerifyBitPermutation();
        VerifyDesKnownAnswer();
        VerifyBlockCipher(new DealCipher(), Hex("00112233445566778899AABBCCDDEEFF"), new byte[16]);
        VerifyBlockCipher(new DealCipher(), Hex("00112233445566778899AABBCCDDEEFF0011223344556677"), new byte[16]);
        VerifyBlockCipher(new DealCipher(), Hex("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"), new byte[16]);
        VerifyModes();
        await VerifyAsyncFiles();
        Console.WriteLine("Все самопроверки Lab1 завершены успешно.");
    }

    private static void VerifyBitPermutation()
    {
        byte[] source = { 0x81 };
        Require(ToHex(Lab1.BitUtils.BitPermutation.Permute(
            source, new[] { 1, 8 }, Lab1.BitUtils.BitOrder.MsbFirst, 1)) == "C0",
            "MSB-first, one-based permutation failed.");
        Require(ToHex(Lab1.BitUtils.BitPermutation.Permute(
            source, new[] { 0, 7 }, Lab1.BitUtils.BitOrder.MsbFirst, 0)) == "C0",
            "MSB-first, zero-based permutation failed.");
        Require(ToHex(Lab1.BitUtils.BitPermutation.Permute(
            source, new[] { 1, 8 }, Lab1.BitUtils.BitOrder.LsbFirst, 1)) == "03",
            "LSB-first, one-based permutation failed.");
        Require(ToHex(Lab1.BitUtils.BitPermutation.Permute(
            source, new[] { 0, 7 }, Lab1.BitUtils.BitOrder.LsbFirst, 0)) == "03",
            "LSB-first, zero-based permutation failed.");
        Console.WriteLine("Перестановки битов: оба порядка и оба начала индексации пройдены.");
    }

    private static void VerifyDesKnownAnswer()
    {
        var des = new DesCipher();
        des.SetKey(Hex("133457799BBCDFF1"));
        byte[] cipher = des.EncryptBlock(Hex("0123456789ABCDEF"));
        Require(ToHex(cipher) == "85E813540F0AB405", "DES known-answer test failed.");
        Require(ToHex(des.DecryptBlock(cipher)) == "0123456789ABCDEF", "DES inverse test failed.");
        Console.WriteLine("DES: контрольный вектор пройден.");
    }

    private static void VerifyBlockCipher(ISymmetricAlgorithm algorithm, byte[] key, byte[] block)
    {
        algorithm.SetKey(key);
        byte[] encrypted = algorithm.EncryptBlock(block);
        Require(encrypted.Length == block.Length, "Block cipher returned an invalid block size.");
        Require(algorithm.DecryptBlock(encrypted).SequenceEqual(block), "Block cipher round-trip failed.");
        Console.WriteLine($"{algorithm.GetType().Name}: проверка блока пройдена.");
    }

    private static void VerifyModes()
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("Lab1 test: arbitrary binary payload.");
        byte[] desKey = Hex("133457799BBCDFF1");
        byte[] dealKey = Hex("00112233445566778899AABBCCDDEEFF");

        foreach (ISymmetricAlgorithm prototype in new ISymmetricAlgorithm[] { new DesCipher(), new DealCipher() })
        {
            byte[] key = prototype is DesCipher ? desKey : dealKey;
            foreach (CipherMode mode in Enum.GetValues(typeof(CipherMode)))
            foreach (PaddingMode padding in Enum.GetValues(typeof(PaddingMode)))
            {
                ISymmetricAlgorithm algorithm = prototype is DesCipher
                    ? new DesCipher()
                    : new DealCipher();
                byte[]? iv = mode == CipherMode.ECB ? null : Enumerable.Range(1, algorithm.BlockSize).Select(i => (byte)i).ToArray();
                var context = new SymmetricCipherContext(algorithm, key, mode, padding, iv);
                byte[] cipher = context.Encrypt(data);
                byte[] recovered = context.Decrypt(cipher);
                Require(recovered.SequenceEqual(data), $"{algorithm.GetType().Name}/{mode}/{padding} round-trip failed.");
                byte[] emptyCipher = context.Encrypt(Array.Empty<byte>());
                Require(context.Decrypt(emptyCipher).Length == 0,
                    $"{algorithm.GetType().Name}/{mode}/{padding} empty-input round-trip failed.");
            }
        }
        Console.WriteLine("Все режимы и варианты набивки прошли round-trip.");
    }

    private static async Task VerifyAsyncFiles()
    {
        byte[] key = Hex("133457799BBCDFF1");
        byte[] iv = new byte[8];
        string input = Path.Combine(Path.GetTempPath(), $"lab1-{Guid.NewGuid():N}.bin");
        string encrypted = Path.Combine(Path.GetTempPath(), $"lab1-{Guid.NewGuid():N}.enc");
        string output = Path.Combine(Path.GetTempPath(), $"lab1-{Guid.NewGuid():N}.out");
        byte[] content = Enumerable.Range(0, 257).Select(i => (byte)(i * 37 + 11)).ToArray();

        try
        {
            await File.WriteAllBytesAsync(input, content);
            var context = new SymmetricCipherContext(new DesCipher(), key, CipherMode.CTR, PaddingMode.PKCS7, iv);
            await context.EncryptAsync(input, encrypted);
            await context.DecryptAsync(encrypted, output);
            Require((await File.ReadAllBytesAsync(output)).SequenceEqual(content), "Asynchronous file round-trip failed.");
            Console.WriteLine("Асинхронное шифрование файла прошло проверку.");
        }
        finally
        {
            DeleteIfExists(input);
            DeleteIfExists(encrypted);
            DeleteIfExists(output);
        }
    }

    private static byte[] Hex(string value)
    {
        byte[] result = new byte[value.Length / 2];
        for (int i = 0; i < result.Length; i++)
            result[i] = Convert.ToByte(value.Substring(i * 2, 2), 16);
        return result;
    }

    private static string ToHex(byte[] value) => Convert.ToHexString(value);

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private static void DeleteIfExists(string path)
    {
        if (File.Exists(path))
            File.Delete(path);
    }
}
