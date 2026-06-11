using System.Text;
using System.Text.Json;
using Cervantes.Contracts;
using Cervantes.CORE.Entities;
using Cervantes.IFR.CveServices;
using Cervantes.IFR.Email;
using Cervantes.Web.Hubs;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Task = System.Threading.Tasks.Task;

namespace Cervantes.Web.Services;

/// <summary>
/// Orchestrates the scheduled CVE exposure re-scan and delivers alerts for newly-found,
/// high-confidence (or KEV) matches via in-app notification, email, and webhook.
/// </summary>
public interface ICveExposureAlertService
{
    /// <summary>Hangfire entry point: re-scan all services, then alert on eligible new matches.</summary>
    Task RunScheduledAsync(CancellationToken ct = default);

    /// <summary>Deliver alerts for un-alerted, non-dismissed, eligible matches.</summary>
    Task<int> ProcessPendingAlertsAsync(CancellationToken ct = default);
}

/// <inheritdoc />
public class CveExposureAlertService : ICveExposureAlertService
{
    private readonly ICveExposureConfiguration _config;
    private readonly ICveMatchingService _matchingService;
    private readonly ITargetServiceCveManager _matchManager;
    private readonly IEmailService _emailService;
    private readonly IHubContext<CveNotificationHub> _hubContext;
    private readonly HttpClient _httpClient;
    private readonly ILogger<CveExposureAlertService> _logger;

    public CveExposureAlertService(
        ICveExposureConfiguration config,
        ICveMatchingService matchingService,
        ITargetServiceCveManager matchManager,
        IEmailService emailService,
        IHubContext<CveNotificationHub> hubContext,
        HttpClient httpClient,
        ILogger<CveExposureAlertService> logger)
    {
        _config = config;
        _matchingService = matchingService;
        _matchManager = matchManager;
        _emailService = emailService;
        _hubContext = hubContext;
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task RunScheduledAsync(CancellationToken ct = default)
    {
        if (!_config.Enabled)
        {
            return;
        }

        _logger.LogInformation("Scheduled CVE exposure scan starting.");
        // Attribution falls back to each service's own owner; pass null for the system run.
        await _matchingService.MatchAllAsync(null, null, ct);
        var alerted = await ProcessPendingAlertsAsync(ct);
        _logger.LogInformation("Scheduled CVE exposure scan complete. {Alerted} alerts delivered.", alerted);
    }

    public async Task<int> ProcessPendingAlertsAsync(CancellationToken ct = default)
    {
        if (!_config.Enabled)
        {
            return 0;
        }

        var pending = await _matchManager.GetAll()
            .Where(m => !m.IsDismissed && !m.AlertSent)
            .Where(m => m.Confidence >= _config.MinConfidenceToAlert ||
                        (_config.AlertOnKevAlways && m.Cve.IsKnownExploited))
            .Include(m => m.Cve)
            .Include(m => m.Target)
            .Include(m => m.TargetService)
            .ToListAsync(ct);

        if (pending.Count == 0)
        {
            return 0;
        }

        var alerted = 0;
        foreach (var match in pending)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                await DeliverAsync(match, ct);
                match.AlertSent = true;
                match.AlertSentDate = DateTime.UtcNow;
                match.ModifiedDate = DateTime.UtcNow;
                _matchManager.Update(match);
                alerted++;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to deliver CVE exposure alert for match {MatchId}.", match.Id);
            }
        }

        await _matchManager.Context.SaveChangesAsync();
        return alerted;
    }

    private async Task DeliverAsync(TargetServiceCve match, CancellationToken ct)
    {
        var cveId = match.Cve?.CveId ?? "CVE";
        var severity = match.Cve?.CvssV3Severity ?? "UNKNOWN";
        var targetName = match.Target?.Name ?? "target";
        var serviceName = match.TargetService?.Name ?? "service";
        var title = $"CVE exposure: {cveId} affects {targetName}";
        var message =
            $"{cveId} ({severity}{(match.Cve?.IsKnownExploited == true ? ", KEV" : "")}) may affect " +
            $"{targetName} via {serviceName} {match.TargetService?.Version} " +
            $"(confidence {match.Confidence:0.00}, {match.MatchType}).";

        if (!string.IsNullOrEmpty(match.UserId))
        {
            // In-app: real-time push via the existing CVE hub (the /cve-exposure page is the
            // persistent surface, so no separate notification row is stored).
            await _hubContext.SendExposureAlertToUser(
                match.UserId, match.Id, title, message,
                match.Cve?.IsKnownExploited == true ? "High" : "Medium",
                cveId, severity, match.Cve?.IsKnownExploited ?? false);

            // Email.
            if (_emailService.IsEnabled())
            {
                await _emailService.SendCveExposureAlertAsync(match.UserId, title, BuildEmailHtml(title, message, match));
            }
        }

        // Webhook.
        if (!string.IsNullOrWhiteSpace(_config.WebhookUrl))
        {
            await PostWebhookAsync(match, cveId, severity, targetName, serviceName, title, message, ct);
        }
    }

    private async Task PostWebhookAsync(
        TargetServiceCve match, string cveId, string severity, string targetName,
        string serviceName, string title, string message, CancellationToken ct)
    {
        var payload = new
        {
            type = "cve_exposure",
            match_id = match.Id,
            cve_id = cveId,
            severity,
            cvss_score = match.Cve?.CvssV3BaseScore,
            known_exploited = match.Cve?.IsKnownExploited ?? false,
            target = targetName,
            service = serviceName,
            service_version = match.TargetService?.Version,
            confidence = match.Confidence,
            match_type = match.MatchType,
            title,
            message,
            created_date = match.CreatedDate
        };

        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        content.Headers.Add("User-Agent", "Cervantes-CVE-Exposure/1.0");
        var response = await _httpClient.PostAsync(_config.WebhookUrl, content, ct);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("CVE exposure webhook returned {Status} for match {MatchId}.",
                (int)response.StatusCode, match.Id);
        }
    }

    private static string BuildEmailHtml(string title, string message, TargetServiceCve match)
    {
        var cve = match.Cve;
        var sb = new StringBuilder();
        sb.Append("<div style=\"font-family:Arial,sans-serif\">");
        sb.Append($"<h2>{System.Net.WebUtility.HtmlEncode(title)}</h2>");
        sb.Append($"<p>{System.Net.WebUtility.HtmlEncode(message)}</p>");
        if (cve != null)
        {
            sb.Append("<ul>");
            sb.Append($"<li><b>CVE:</b> {System.Net.WebUtility.HtmlEncode(cve.CveId)}</li>");
            sb.Append($"<li><b>Severity:</b> {System.Net.WebUtility.HtmlEncode(cve.CvssV3Severity ?? "")} ({cve.CvssV3BaseScore})</li>");
            sb.Append($"<li><b>Known exploited (KEV):</b> {(cve.IsKnownExploited ? "Yes" : "No")}</li>");
            sb.Append($"<li><b>Confidence:</b> {match.Confidence:0.00} ({System.Net.WebUtility.HtmlEncode(match.MatchType)})</li>");
            sb.Append("</ul>");
            if (!string.IsNullOrEmpty(cve.Description))
            {
                sb.Append($"<p>{System.Net.WebUtility.HtmlEncode(cve.Description)}</p>");
            }
        }
        sb.Append("</div>");
        return sb.ToString();
    }
}
