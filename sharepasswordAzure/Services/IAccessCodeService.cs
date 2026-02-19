namespace SharePassword.Services;

public interface IAccessCodeService
{
    string GenerateCode();
    string HashCode(string code);
    bool Verify(string code, string hash);
}
