using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace SharePassword.Data.Migrations.SqlServer;

[DbContext(typeof(SqlServerSharePasswordDbContext))]
[Migration(MigrationId)]
public partial class ClientEncryptedSharesSqlServer : Migration
{
    public const string MigrationId = "20260503000200_ClientEncryptedSharesSqlServer";

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "SecretEncryptionMode",
            table: "PasswordShares",
            type: "nvarchar(32)",
            maxLength: 32,
            nullable: false,
            defaultValue: "server-managed");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(name: "SecretEncryptionMode", table: "PasswordShares");
    }
}
