using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace SharePassword.Data.Migrations.Postgresql;

[DbContext(typeof(PostgresqlSharePasswordDbContext))]
[Migration(MigrationId)]
public partial class ClientEncryptedSharesPostgresql : Migration
{
    public const string MigrationId = "20260503000300_ClientEncryptedSharesPostgresql";

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "SecretEncryptionMode",
            table: "PasswordShares",
            type: "character varying(32)",
            maxLength: 32,
            nullable: false,
            defaultValue: "server-managed");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(name: "SecretEncryptionMode", table: "PasswordShares");
    }
}
