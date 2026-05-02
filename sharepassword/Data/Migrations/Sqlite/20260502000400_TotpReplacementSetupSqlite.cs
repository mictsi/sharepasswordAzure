using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace SharePassword.Data.Migrations.Sqlite;

[DbContext(typeof(SqliteSharePasswordDbContext))]
[Migration(MigrationId)]
public partial class TotpReplacementSetupSqlite : Migration
{
    public const string MigrationId = "20260502000400_TotpReplacementSetupSqlite";

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<DateTime>(
            name: "PendingTotpCreatedAtUtc",
            table: "LocalUsers",
            type: "TEXT",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "PendingTotpSecretEncrypted",
            table: "LocalUsers",
            type: "TEXT",
            maxLength: 512,
            nullable: false,
            defaultValue: string.Empty);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(name: "PendingTotpCreatedAtUtc", table: "LocalUsers");
        migrationBuilder.DropColumn(name: "PendingTotpSecretEncrypted", table: "LocalUsers");
    }
}
