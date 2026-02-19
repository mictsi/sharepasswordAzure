namespace SharePassword.Services;

public interface IPasswordCryptoService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
}
