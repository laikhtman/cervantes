using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Cervantes.DAL.Migrations
{
    /// <inheritdoc />
    public partial class AddTargetServiceCve : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "TargetServiceCves",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TargetServiceId = table.Column<Guid>(type: "uuid", nullable: false),
                    TargetId = table.Column<Guid>(type: "uuid", nullable: false),
                    CveId = table.Column<Guid>(type: "uuid", nullable: false),
                    CveConfigurationId = table.Column<Guid>(type: "uuid", nullable: true),
                    MatchType = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    Confidence = table.Column<double>(type: "double precision", nullable: false),
                    MatchedProduct = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    MatchedVersion = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    IsDismissed = table.Column<bool>(type: "boolean", nullable: false),
                    IsValidated = table.Column<bool>(type: "boolean", nullable: false),
                    AlertSent = table.Column<bool>(type: "boolean", nullable: false),
                    AlertSentDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ModifiedDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TargetServiceCves", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TargetServiceCves_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_TargetServiceCves_CveConfigurations_CveConfigurationId",
                        column: x => x.CveConfigurationId,
                        principalTable: "CveConfigurations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_TargetServiceCves_Cves_CveId",
                        column: x => x.CveId,
                        principalTable: "Cves",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_TargetServiceCves_TargetServices_TargetServiceId",
                        column: x => x.TargetServiceId,
                        principalTable: "TargetServices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_TargetServiceCves_Targets_TargetId",
                        column: x => x.TargetId,
                        principalTable: "Targets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TargetServiceCves_CveConfigurationId",
                table: "TargetServiceCves",
                column: "CveConfigurationId");

            migrationBuilder.CreateIndex(
                name: "IX_TargetServiceCves_CveId",
                table: "TargetServiceCves",
                column: "CveId");

            migrationBuilder.CreateIndex(
                name: "IX_TargetServiceCves_TargetId",
                table: "TargetServiceCves",
                column: "TargetId");

            migrationBuilder.CreateIndex(
                name: "IX_TargetServiceCves_TargetServiceId_CveId",
                table: "TargetServiceCves",
                columns: new[] { "TargetServiceId", "CveId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TargetServiceCves_UserId",
                table: "TargetServiceCves",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TargetServiceCves");
        }
    }
}
