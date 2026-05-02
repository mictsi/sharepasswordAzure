using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace SharePassword.Data.Migrations.SqlServer;

[DbContext(typeof(SqlServerSharePasswordDbContext))]
[Migration(MigrationId)]
public partial class SecurityFeaturesSqlServer : Migration
{
    public const string MigrationId = "20260502000200_SecurityFeaturesSqlServer";

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<DateTime>(
            name: "AccessPausedUntilUtc",
            table: "PasswordShares",
            type: "datetime2",
            nullable: true);

        migrationBuilder.AddColumn<int>(
            name: "FailedAccessAttempts",
            table: "PasswordShares",
            type: "int",
            nullable: false,
            defaultValue: 0);

        migrationBuilder.AddColumn<bool>(
            name: "IsTotpRequired",
            table: "LocalUsers",
            type: "bit",
            nullable: false,
            defaultValue: false);

        migrationBuilder.AddColumn<long>(
            name: "LastTotpTimeStepMatched",
            table: "LocalUsers",
            type: "bigint",
            nullable: true);

        migrationBuilder.AddColumn<DateTime>(
            name: "LastTotpResetAtUtc",
            table: "LocalUsers",
            type: "datetime2",
            nullable: true);

        migrationBuilder.AddColumn<DateTime>(
            name: "TotpConfirmedAtUtc",
            table: "LocalUsers",
            type: "datetime2",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "TotpSecretEncrypted",
            table: "LocalUsers",
            type: "nvarchar(512)",
            maxLength: 512,
            nullable: false,
            defaultValue: string.Empty);

        migrationBuilder.AddColumn<int>(
            name: "ShareAccessFailedAttemptLimit",
            table: "SystemConfigurations",
            type: "int",
            nullable: false,
            defaultValue: 5);

        migrationBuilder.AddColumn<int>(
            name: "ShareAccessPauseMinutes",
            table: "SystemConfigurations",
            type: "int",
            nullable: false,
            defaultValue: 15);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(name: "AccessPausedUntilUtc", table: "PasswordShares");
        migrationBuilder.DropColumn(name: "FailedAccessAttempts", table: "PasswordShares");
        migrationBuilder.DropColumn(name: "IsTotpRequired", table: "LocalUsers");
        migrationBuilder.DropColumn(name: "LastTotpTimeStepMatched", table: "LocalUsers");
        migrationBuilder.DropColumn(name: "LastTotpResetAtUtc", table: "LocalUsers");
        migrationBuilder.DropColumn(name: "TotpConfirmedAtUtc", table: "LocalUsers");
        migrationBuilder.DropColumn(name: "TotpSecretEncrypted", table: "LocalUsers");
        migrationBuilder.DropColumn(name: "ShareAccessFailedAttemptLimit", table: "SystemConfigurations");
        migrationBuilder.DropColumn(name: "ShareAccessPauseMinutes", table: "SystemConfigurations");
    }
}
