namespace Lab1.Interfaces;

public interface IKeyExpander
{
    byte[][] Expandkey(byte[] key);
}

public interface IRoundtransform
{
    byte[] Transform(byte[] blockPart, byte[] roundKey);
}

public interface ISymmetricAlgorithm
{
    int BlockSize { get; }
    void SetKey(byte[] key);
    byte[] EncryptBlock(byte[] block);
    byte[] DecryptBlock(byte[] block);
}

public enum CipherMode
{
    ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta
}

public enum PaddingMode
{
    Zeros, ANSIX923, PKCS7, ISO10126
}