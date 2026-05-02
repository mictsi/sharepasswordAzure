namespace SharePassword.Services;

public interface ITotpService
{
    string GenerateSecretKey();
    TotpSetupDetails BuildSetup(string secretKey, string accountName);
    bool VerifyCode(string secretKey, string code, long? lastTimeStepMatched, out long timeStepMatched);
}
