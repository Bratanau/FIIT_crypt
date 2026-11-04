using System;
using System.Text;
using BitUtils;

class Program
{
    static void Main()
    {
        byte[] block = Encoding.ASCII.GetBytes("ABCDEFG");

        var result = BitPermutation.Permute(block, DesTables.IP, BitOrder.msbFirst, 1);

        PrintByteAsBinary(result);
    }

    static void PrintByteAsBinary(byte[] bytes)
    {
        for (int i = 0; i < bytes.Length; i++)
        {
            string binaryString = Convert.ToString(bytes[i], 2).PadLeft(8, '0');
            Console.Write($"{binaryString}");

            if ((i + 1) % 4 == 0) Console.WriteLine();
        }
    }
}