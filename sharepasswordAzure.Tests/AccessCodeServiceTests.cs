using SharePassword.Services;

namespace SharePassword.Tests;

public class AccessCodeServiceTests
{
    private readonly AccessCodeService _service = new();

    [Fact]
    public void GenerateCode_Returns8Chars_UsingExpectedAlphabet()
    {
        var code = _service.GenerateCode();

        Assert.Equal(8, code.Length);
        Assert.Matches("^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$", code);
    }

    [Fact]
    public void Verify_ReturnsTrueForCorrectCode_FalseForIncorrectCode()
    {
        const string code = "ABCD2345";
        var hash = _service.HashCode(code);

        Assert.True(_service.Verify(code, hash));
        Assert.False(_service.Verify("ZZZZ9999", hash));
    }
}
