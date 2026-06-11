using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cervantes.Contracts;
using Cervantes.CORE.Entities;
using Microsoft.Extensions.Logging;
using Task = System.Threading.Tasks.Task;

namespace Cervantes.IFR.Subdomain;

/// <summary>
/// Queries MerkleMap and SecurityTrails for subdomains and imports them as Hostname targets.
/// Each provider is isolated: a failure in one (rate limit, auth, network) is logged and skipped
/// so the other still contributes results.
/// </summary>
public class SubdomainService : ISubdomainService
{
    private readonly HttpClient _httpClient;
    private readonly ISubdomainConfiguration _config;
    private readonly ITargetManager _targetManager;
    private readonly ILogger<SubdomainService> _logger;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public SubdomainService(
        HttpClient httpClient,
        ISubdomainConfiguration config,
        ITargetManager targetManager,
        ILogger<SubdomainService> logger)
    {
        _httpClient = httpClient;
        _config = config;
        _targetManager = targetManager;
        _logger = logger;
    }

    public bool Enabled =>
        _config.Enabled &&
        (!string.IsNullOrWhiteSpace(_config.MerkleMapApiKey) ||
         !string.IsNullOrWhiteSpace(_config.SecurityTrailsApiKey));

    public async Task<IReadOnlyList<string>> EnumerateAsync(string domain, CancellationToken ct = default)
    {
        domain = NormalizeDomain(domain);
        if (string.IsNullOrEmpty(domain))
        {
            return Array.Empty<string>();
        }

        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(_config.MerkleMapApiKey))
        {
            foreach (var host in await QueryMerkleMapAsync(domain, ct))
            {
                results.Add(host);
            }
        }

        if (!string.IsNullOrWhiteSpace(_config.SecurityTrailsApiKey))
        {
            foreach (var host in await QuerySecurityTrailsAsync(domain, ct))
            {
                results.Add(host);
            }
        }

        // Never return the apex domain itself as a "discovered subdomain".
        results.Remove(domain);
        return results.ToList();
    }

    public async Task<SubdomainImportResult> DiscoverAndImportAsync(Guid targetId, string userId, CancellationToken ct = default)
    {
        if (!Enabled)
        {
            return new SubdomainImportResult { Status = SubdomainImportStatus.Disabled };
        }

        var target = _targetManager.GetAll().FirstOrDefault(x => x.Id == targetId);
        if (target == null)
        {
            return new SubdomainImportResult { Status = SubdomainImportStatus.TargetNotFound };
        }

        if (target.Type != TargetType.URL && target.Type != TargetType.Hostname)
        {
            return new SubdomainImportResult { Status = SubdomainImportStatus.NotEligible };
        }

        var domain = NormalizeDomain(ExtractHost(target.Name, target.Type));
        if (string.IsNullOrEmpty(domain))
        {
            return new SubdomainImportResult { Status = SubdomainImportStatus.NoDomain };
        }

        var subdomains = await EnumerateAsync(domain, ct);
        var result = new SubdomainImportResult
        {
            Status = SubdomainImportStatus.Success,
            Domain = domain,
            Found = subdomains.Count
        };

        if (subdomains.Count == 0)
        {
            return result;
        }

        // Dedupe against existing target names in the same project (case-insensitive).
        var existing = _targetManager.GetAll()
            .Where(x => x.ProjectId == target.ProjectId)
            .Select(x => x.Name)
            .ToList();
        var existingSet = new HashSet<string>(
            existing.Where(n => n != null),
            StringComparer.OrdinalIgnoreCase);

        foreach (var sub in subdomains)
        {
            if (existingSet.Contains(sub))
            {
                result.Skipped++;
                continue;
            }

            _targetManager.Add(new Target
            {
                Name = sub,
                Description = "Discovered via subdomain enumeration",
                Type = TargetType.Hostname,
                ProjectId = target.ProjectId,
                UserId = userId
            });
            existingSet.Add(sub);
            result.Created++;
        }

        if (result.Created > 0)
        {
            _targetManager.Context.SaveChanges();
        }

        _logger.LogInformation(
            "Subdomain discovery for {Domain}: found {Found}, created {Created}, skipped {Skipped}.",
            domain, result.Found, result.Created, result.Skipped);

        return result;
    }

    public async Task RunScheduledAsync(CancellationToken ct = default)
    {
        if (!Enabled)
        {
            return;
        }

        // Snapshot eligible targets up front so subdomains created during the run are not
        // themselves re-enumerated in the same pass.
        var eligible = _targetManager.GetAll()
            .Where(x => x.Type == TargetType.URL || x.Type == TargetType.Hostname)
            .Select(x => new { x.Id, x.UserId })
            .ToList();

        _logger.LogInformation("Scheduled subdomain enumeration starting for {Count} targets.", eligible.Count);

        foreach (var t in eligible)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                await DiscoverAndImportAsync(t.Id, t.UserId, ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Scheduled subdomain enumeration failed for target {TargetId}.", t.Id);
            }
        }
    }

    // ----- Providers -------------------------------------------------------

    private async Task<IReadOnlyList<string>> QueryMerkleMapAsync(string domain, CancellationToken ct)
    {
        var hosts = new List<string>();
        try
        {
            var baseUrl = _config.MerkleMapBaseUrl.TrimEnd('/');
            for (var page = 0; page < Math.Max(1, _config.MaxMerkleMapPages); page++)
            {
                var url = $"{baseUrl}/v1/search?query={Uri.EscapeDataString(domain)}&type=wildcard&page={page}";
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _config.MerkleMapApiKey);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                using var response = await _httpClient.SendAsync(request, ct);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("MerkleMap returned {Status} for {Domain} (page {Page}).",
                        (int)response.StatusCode, domain, page);
                    break;
                }

                var payload = await response.Content.ReadFromJsonAsync<MerkleMapResponse>(JsonOptions, ct);
                var results = payload?.Results;
                if (results == null || results.Count == 0)
                {
                    break;
                }

                foreach (var item in results)
                {
                    if (TryNormalizeHost(item.Hostname, domain, out var host))
                    {
                        hosts.Add(host);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error querying MerkleMap for {Domain}.", domain);
        }

        return hosts;
    }

    private async Task<IReadOnlyList<string>> QuerySecurityTrailsAsync(string domain, CancellationToken ct)
    {
        var hosts = new List<string>();
        try
        {
            var baseUrl = _config.SecurityTrailsBaseUrl.TrimEnd('/');
            var url = $"{baseUrl}/domain/{Uri.EscapeDataString(domain)}/subdomains?children_only=false";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("apikey", _config.SecurityTrailsApiKey);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var response = await _httpClient.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("SecurityTrails returned {Status} for {Domain}.",
                    (int)response.StatusCode, domain);
                return hosts;
            }

            var payload = await response.Content.ReadFromJsonAsync<SecurityTrailsResponse>(JsonOptions, ct);
            var subdomains = payload?.Subdomains;
            if (subdomains == null)
            {
                return hosts;
            }

            foreach (var entry in subdomains)
            {
                if (string.IsNullOrWhiteSpace(entry))
                {
                    continue;
                }

                // SecurityTrails returns bare prefixes ("www", "mail"); be defensive in case a
                // full hostname is ever returned.
                var candidate = entry.Trim().TrimEnd('.').EndsWith("." + domain, StringComparison.OrdinalIgnoreCase)
                    ? entry
                    : $"{entry}.{domain}";

                if (TryNormalizeHost(candidate, domain, out var host))
                {
                    hosts.Add(host);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error querying SecurityTrails for {Domain}.", domain);
        }

        return hosts;
    }

    // ----- Helpers ---------------------------------------------------------

    /// <summary>Extracts the bare host from a target name, parsing URLs when needed.</summary>
    private static string ExtractHost(string name, TargetType type)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return string.Empty;
        }

        name = name.Trim();
        if (type == TargetType.Hostname)
        {
            return name;
        }

        // URL: try a real parse, falling back to a tolerant manual strip.
        if (Uri.TryCreate(name, UriKind.Absolute, out var uri))
        {
            return uri.Host;
        }
        if (Uri.TryCreate("http://" + name, UriKind.Absolute, out var uri2))
        {
            return uri2.Host;
        }
        return name;
    }

    private static string NormalizeDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return string.Empty;
        }
        return domain.Trim().TrimEnd('.').TrimStart('*', '.').ToLowerInvariant();
    }

    /// <summary>
    /// Normalizes a candidate hostname and keeps it only if it is a subdomain of (or equal to)
    /// <paramref name="domain"/>. Strips wildcard labels.
    /// </summary>
    private static bool TryNormalizeHost(string candidate, string domain, out string host)
    {
        host = string.Empty;
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        host = candidate.Trim().TrimEnd('.').TrimStart('*', '.').ToLowerInvariant();
        if (host.Length == 0)
        {
            return false;
        }

        return host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
               host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
    }

    // ----- Provider response DTOs -----------------------------------------

    private sealed class MerkleMapResponse
    {
        [JsonPropertyName("count")] public int Count { get; set; }
        [JsonPropertyName("results")] public List<MerkleMapResult>? Results { get; set; }
    }

    private sealed class MerkleMapResult
    {
        [JsonPropertyName("hostname")] public string? Hostname { get; set; }
    }

    private sealed class SecurityTrailsResponse
    {
        [JsonPropertyName("subdomains")] public List<string>? Subdomains { get; set; }
    }
}
