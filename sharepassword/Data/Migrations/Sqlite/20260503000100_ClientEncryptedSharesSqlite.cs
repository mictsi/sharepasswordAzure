using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace SharePassword.Data.Migrations.Sqlite;

[DbContext(typeof(SqliteSharePasswordDbContext))]
[Migration(MigrationId)]
public partial class ClientEncryptedSharesSqlite : Migration
{
    public const string MigrationId = "20260503000100_ClientEncryptedSharesSqlite";

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "SecretEncryptionMode",
            table: "PasswordShares",
            type: "TEXT",
            maxLength: 32,
            nullable: false,
            defaultValue: "server-managed");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(name: "SecretEncryptionMode", table: "PasswordShares");
    }
}
