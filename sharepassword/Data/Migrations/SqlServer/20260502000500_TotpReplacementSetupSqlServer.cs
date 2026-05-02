using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace SharePassword.Data.Migrations.SqlServer;

[DbContext(typeof(SqlServerSharePasswordDbContext))]
[Migration(MigrationId)]
public partial class TotpReplacementSetupSqlServer : Migration
{
    public const string MigrationId = "20260502000500_TotpReplacementSetupSqlServer";

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<DateTime>(
            name: "PendingTotpCreatedAtUtc",
            table: "LocalUsers",
            type: "datetime2",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "PendingTotpSecretEncrypted",
            table: "LocalUsers",
            type: "nvarchar(512)",
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
