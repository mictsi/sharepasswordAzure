using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace SharePassword.Data.Migrations.Postgresql;

[DbContext(typeof(PostgresqlSharePasswordDbContext))]
[Migration(MigrationId)]
public partial class TotpReplacementSetupPostgresql : Migration
{
    public const string MigrationId = "20260502000600_TotpReplacementSetupPostgresql";

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<DateTime>(
            name: "PendingTotpCreatedAtUtc",
            table: "LocalUsers",
            type: "timestamp with time zone",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "PendingTotpSecretEncrypted",
            table: "LocalUsers",
            type: "character varying(512)",
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
