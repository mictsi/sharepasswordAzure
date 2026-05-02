using OtpNet;
using QRCoder;

namespace SharePassword.Services;

public sealed class TotpService : ITotpService
{
    private const string Issuer = "SharePassword";
    private const int SecretLengthBytes = 20;
    private const int TotpDigits = 6;
    private const int TotpPeriodSeconds = 30;

    public string GenerateSecretKey()
    {
        return Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(SecretLengthBytes));
    }

    public TotpSetupDetails BuildSetup(string secretKey, string accountName)
    {
        var normalizedSecret = NormalizeSecret(secretKey);
        var normalizedAccountName = string.IsNullOrWhiteSpace(accountName) ? "local-user" : accountName.Trim();
        var provisioningUri = new OtpUri(
            OtpType.Totp,
            normalizedSecret,
            normalizedAccountName,
            Issuer,
            OtpHashMode.Sha1,
            TotpDigits,
            TotpPeriodSeconds,
            0).ToString();

        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(provisioningUri, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new SvgQRCode(qrCodeData);

        return new TotpSetupDetails
        {
            SecretKey = normalizedSecret,
            ProvisioningUri = provisioningUri,
            QrCodeSvg = qrCode.GetGraphic(8)
        };
    }

    public bool VerifyCode(string secretKey, string code, long? lastTimeStepMatched, out long timeStepMatched)
    {
        timeStepMatched = 0;
        var normalizedCode = (code ?? string.Empty).Trim().Replace(" ", string.Empty, StringComparison.Ordinal);
        if (normalizedCode.Length != TotpDigits || !normalizedCode.All(char.IsDigit))
        {
            return false;
        }

        var secretBytes = Base32Encoding.ToBytes(NormalizeSecret(secretKey));
        var totp = new Totp(secretBytes);
        if (!totp.VerifyTotp(normalizedCode, out timeStepMatched, VerificationWindow.RfcSpecifiedNetworkDelay))
        {
            return false;
        }

        return !lastTimeStepMatched.HasValue || timeStepMatched > lastTimeStepMatched.Value;
    }

    private static string NormalizeSecret(string secretKey)
    {
        return (secretKey ?? string.Empty).Trim().Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
    }
}
