using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace SharePassword.Data.Migrations.SqlServer;

[DbContext(typeof(SqlServerSharePasswordDbContext))]
[Migration(MigrationId)]
public partial class PlatformFeaturesSqlServer : Migration
{
    public const string MigrationId = "20260430000200_PlatformFeaturesSqlServer";

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "LocalUsers",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                Username = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                DisplayName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                Email = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                PasswordHash = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                Roles = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                IsDisabled = table.Column<bool>(type: "bit", nullable: false),
                IsSeededAdmin = table.Column<bool>(type: "bit", nullable: false),
                CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                LastLoginAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                LastShareCreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                LastPasswordResetAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                TotalSuccessfulLogins = table.Column<int>(type: "int", nullable: false),
                TotalSharesCreated = table.Column<int>(type: "int", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_LocalUsers", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "SystemConfigurations",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false),
                TimeZoneId = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                SmtpHost = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                SmtpPort = table.Column<int>(type: "int", nullable: false),
                SmtpUsername = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                SmtpPassword = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                UseTls = table.Column<bool>(type: "bit", nullable: false),
                SenderEmail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                SenderDisplayName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                AdminNotificationRecipients = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                NotifyAdminsOnShareAccess = table.Column<bool>(type: "bit", nullable: false),
                NotifyCreatorOnShareAccess = table.Column<bool>(type: "bit", nullable: false),
                ShareAccessedSubjectTemplate = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                ShareAccessedBodyTemplate = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: false),
                UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                UpdatedBy = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SystemConfigurations", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "UsageMetricCounters",
            columns: table => new
            {
                Key = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                Count = table.Column<long>(type: "bigint", nullable: false),
                UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_UsageMetricCounters", x => x.Key);
            });

        migrationBuilder.CreateTable(
            name: "UsageMetricEvents",
            columns: table => new
            {
                Id = table.Column<long>(type: "bigint", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                TimestampUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                MetricKey = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                ActorType = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                ActorIdentifier = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                Increment = table.Column<long>(type: "bigint", nullable: false),
                RelatedId = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                Details = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true)
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