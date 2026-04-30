using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace SharePassword.Data.Migrations.Sqlite;

[DbContext(typeof(SqliteSharePasswordDbContext))]
[Migration(MigrationId)]
public partial class PlatformFeaturesSqlite : Migration
{
    public const string MigrationId = "20260430000100_PlatformFeaturesSqlite";

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "LocalUsers",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "TEXT", nullable: false),
                Username = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                DisplayName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                Email = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                PasswordHash = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                Roles = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                IsDisabled = table.Column<bool>(type: "INTEGER", nullable: false),
                IsSeededAdmin = table.Column<bool>(type: "INTEGER", nullable: false),
                CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                LastLoginAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                LastShareCreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                LastPasswordResetAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                TotalSuccessfulLogins = table.Column<int>(type: "INTEGER", nullable: false),
                TotalSharesCreated = table.Column<int>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_LocalUsers", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "SystemConfigurations",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false),
                TimeZoneId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                SmtpHost = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                SmtpPort = table.Column<int>(type: "INTEGER", nullable: false),
                SmtpUsername = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                SmtpPassword = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                UseTls = table.Column<bool>(type: "INTEGER", nullable: false),
                SenderEmail = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                SenderDisplayName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                AdminNotificationRecipients = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                NotifyAdminsOnShareAccess = table.Column<bool>(type: "INTEGER", nullable: false),
                NotifyCreatorOnShareAccess = table.Column<bool>(type: "INTEGER", nullable: false),
                ShareAccessedSubjectTemplate = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                ShareAccessedBodyTemplate = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: false),
                UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                UpdatedBy = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SystemConfigurations", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "UsageMetricCounters",
            columns: table => new
            {
                Key = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                Count = table.Column<long>(type: "INTEGER", nullable: false),
                UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_UsageMetricCounters", x => x.Key);
            });

        migrationBuilder.CreateTable(
            name: "UsageMetricEvents",
            columns: table => new
            {
                Id = table.Column<long>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                TimestampUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                MetricKey = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                ActorType = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                ActorIdentifier = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                Increment = table.Column<long>(type: "INTEGER", nullable: false),
                RelatedId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                Details = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_UsageMetricEvents", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_LocalUsers_Email",
            table: "LocalUsers",
            column: "Email");

        migrationBuilder.CreateIndex(
            name: "IX_LocalUsers_Username",
            table: "LocalUsers",
            column: "Username",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_UsageMetricEvents_MetricKey",
            table: "UsageMetricEvents",
            column: "MetricKey");

        migrationBuilder.CreateIndex(
            name: "IX_UsageMetricEvents_TimestampUtc",
            table: "UsageMetricEvents",
            column: "TimestampUtc");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "LocalUsers");
        migrationBuilder.DropTable(name: "SystemConfigurations");
        migrationBuilder.DropTable(name: "UsageMetricCounters");
        migrationBuilder.DropTable(name: "UsageMetricEvents");
    }
}