using System.Text.RegularExpressions;
using Cervantes.Contracts;
using Cervantes.CORE.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Task = System.Threading.Tasks.Task;

namespace Cervantes.IFR.CveServices;

/// <summary>
/// Correlates target services against CVE CPE configurations with a tiered, scored match.
/// </summary>
public class CveMatchingService : ICveMatchingService
{
    private readonly ITargetServicesManager _targetServicesManager;
    private readonly ITargetServiceCveManager _matchManager;
    private readonly ICveManager _cveManager;
    private readonly ILogger<CveMatchingService> _logger;

    // Tokens that carry no product identity and only add noise to the match key.
    private static readonly string[] NoiseTokens =
        { "httpd", "server", "service", "daemon", "openbsd", "ubuntu", "debian", "the" };

    private static readonly Regex VersionRegex = new(@"\d+(\.\d+)+", RegexOptions.Compiled);

    public CveMatchingService(
        ITargetServicesManager targetServicesManager,
        ITargetServiceCveManager matchManager,
        ICveManager cveManager,
        ILogger<CveMatchingService> logger)
    {
        _targetServicesManager = targetServicesManager;
        _matchManager = matchManager;
        _cveManager = cveManager;
        _logger = logger;
    }

    public async Task<CveExposureScanResult> MatchServiceAsync(Guid targetServiceId, string userId, CancellationToken ct = default)
    {
        var service = await _targetServicesManager.GetAll()
            .FirstOrDefaultAsync(x => x.Id == targetServiceId, ct);
        if (service == null)
        {
            return new CveExposureScanResult();
        }

        var index = await BuildProductIndexAsync(ct);
        var result = new CveExposureScanResult();
        await MatchOneServiceAsync(service, index, userId, result, ct);
        await _matchManager.Context.SaveChangesAsync();
        return result;
    }

    public async Task<CveExposureScanResult> MatchTargetAsync(Guid targetId, string userId, CancellationToken ct = default)
    {
        var services = await _targetServicesManager.GetAll()
            .Where(x => x.TargetId == targetId)
            .ToListAsync(ct);

        var index = await BuildProductIndexAsync(ct);
        var result = new CveExposureScanResult();
        foreach (var service in services)
        {
            ct.ThrowIfCancellationRequested();
            await MatchOneServiceAsync(service, index, userId, result, ct);
        }
        await _matchManager.Context.SaveChangesAsync();
        return result;
    }

    public async Task<CveExposureScanResult> MatchAllAsync(Guid? projectId, string userId, CancellationToken ct = default)
    {
        var query = _targetServicesManager.GetAll().Include(x => x.Target).AsQueryable();
        if (projectId.HasValue)
        {
            query = query.Where(x => x.Target.ProjectId == projectId.Value);
        }
        var services = await query.ToListAsync(ct);

        var index = await BuildProductIndexAsync(ct);
        var result = new CveExposureScanResult();
        foreach (var service in services)
        {
            ct.ThrowIfCancellationRequested();
            await MatchOneServiceAsync(service, index, userId, result, ct);
        }
        await _matchManager.Context.SaveChangesAsync();

        _logger.LogInformation(
            "CVE exposure scan complete: scanned {Scanned}, matches {Matches}, created {Created}, updated {Updated}, skipped {Skipped}.",
            result.ServicesScanned, result.Matches, result.Created, result.Updated, result.Skipped);
        return result;
    }

    public async Task<IReadOnlyList<TargetServiceCve>> MatchNewCvesAsync(IEnumerable<Guid> cveIds, string userId, CancellationToken ct = default)
    {
        var ids = cveIds?.Distinct().ToList() ?? new List<Guid>();
        if (ids.Count == 0)
        {
            return Array.Empty<TargetServiceCve>();
        }

        // Only the configurations belonging to the newly-synced CVEs.
        var configs = await _matchManager.Context.Set<CveConfiguration>()
            .Where(c => c.IsVulnerable && ids.Contains(c.CveId))
            .ToListAsync(ct);
        var index = BuildIndex(configs);
        if (index.Count == 0)
        {
            return Array.Empty<TargetServiceCve>();
        }

        var services = await _targetServicesManager.GetAll().ToListAsync(ct);
        var created = new List<TargetServiceCve>();
        var result = new CveExposureScanResult();
        foreach (var service in services)
        {
            ct.ThrowIfCancellationRequested();
            var before = result.Created;
            var newOnes = await MatchOneServiceAsync(service, index, userId, result, ct);
            if (result.Created > before)
            {
                created.AddRange(newOnes);
            }
        }
        await _matchManager.Context.SaveChangesAsync();
        return created;
    }

    // ----- Core matching --------------------------------------------------

    /// <summary>
    /// Scores a single service against the product index and upserts matches.
    /// Returns the newly-created records (for alerting).
    /// </summary>
    private async Task<List<TargetServiceCve>> MatchOneServiceAsync(
        TargetServices service,
        Dictionary<string, List<CveConfiguration>> index,
        string userId,
        CveExposureScanResult result,
        CancellationToken ct)
    {
        result.ServicesScanned++;
        var created = new List<TargetServiceCve>();

        var product = NormalizeProduct(service.Name);
        if (string.IsNullOrEmpty(product))
        {
            return created;
        }
        var version = ParseVersion(service.Version) ?? ParseVersion(service.Name);

        // Best match per CVE for this service.
        var best = new Dictionary<Guid, (CveConfiguration config, double confidence, string matchType, bool isKeyword)>();
        foreach (var (key, configs) in index)
        {
            if (!ProductsMatch(product, key))
            {
                continue;
            }
            foreach (var config in configs)
            {
                var (confidence, matchType) = Score(config, version);
                if (confidence <= 0)
                {
                    continue;
                }
                if (!best.TryGetValue(config.CveId, out var existing) || confidence > existing.confidence)
                {
                    best[config.CveId] = (config, confidence, matchType, false);
                }
            }
        }

        // Keyword fallback: product name present but no usable config produced a match.
        if (best.Count == 0 && index.TryGetValue(product, out var exact) && exact.Count > 0)
        {
            foreach (var config in exact)
            {
                if (!best.ContainsKey(config.CveId))
                {
                    best[config.CveId] = (config, 0.30, "KeywordFallback", true);
                }
            }
        }

        foreach (var (cveId, match) in best)
        {
            result.Matches++;
            var existing = await _matchManager.GetAll()
                .FirstOrDefaultAsync(x => x.TargetServiceId == service.Id && x.CveId == cveId, ct);

            if (existing != null)
            {
                if (existing.IsDismissed)
                {
                    result.Skipped++;
                    continue;
                }
                if (match.confidence > existing.Confidence)
                {
                    existing.Confidence = match.confidence;
                    existing.MatchType = match.matchType;
                    existing.CveConfigurationId = match.isKeyword ? null : match.config.Id;
                    existing.MatchedProduct = product;
                    existing.MatchedVersion = version?.ToString() ?? string.Empty;
                    existing.ModifiedDate = DateTime.UtcNow;
                    _matchManager.Update(existing);
                    result.Updated++;
                }
                else
                {
                    result.Skipped++;
                }
                continue;
            }

            var record = new TargetServiceCve
            {
                TargetServiceId = service.Id,
                TargetId = service.TargetId,
                CveId = cveId,
                CveConfigurationId = match.isKeyword ? null : match.config.Id,
                MatchType = match.matchType,
                Confidence = match.confidence,
                MatchedProduct = product,
                MatchedVersion = version?.ToString() ?? string.Empty,
                UserId = string.IsNullOrEmpty(service.UserId) ? userId : service.UserId,
                CreatedDate = DateTime.UtcNow,
                ModifiedDate = DateTime.UtcNow
            };
            await _matchManager.AddAsync(record);
            created.Add(record);
            result.Created++;
        }

        return created;
    }

    /// <summary>
    /// Scores a config against a parsed service version. Returns (confidence, matchType);
    /// confidence 0 means no match.
    /// </summary>
    private static (double confidence, string matchType) Score(CveConfiguration config, Version version)
    {
        // Exact pinned version.
        var configVersion = ParseVersion(config.Version);
        if (version != null && configVersion != null && version == configVersion)
        {
            return (0.95, "CpeVersionRange");
        }

        // Range bounds.
        var hasRange =
            !string.IsNullOrWhiteSpace(config.VersionStartIncluding) ||
            !string.IsNullOrWhiteSpace(config.VersionStartExcluding) ||
            !string.IsNullOrWhiteSpace(config.VersionEndIncluding) ||
            !string.IsNullOrWhiteSpace(config.VersionEndExcluding);

        if (version != null && hasRange && InRange(version, config))
        {
            return (0.85, "CpeVersionRange");
        }

        // Product matched but the version could not be compared on one side.
        if (version == null || (configVersion == null && !hasRange))
        {
            return (0.50, "CpeProductOnly");
        }

        return (0, string.Empty);
    }

    private static bool InRange(Version version, CveConfiguration config)
    {
        var startIncl = ParseVersion(config.VersionStartIncluding);
        var startExcl = ParseVersion(config.VersionStartExcluding);
        var endIncl = ParseVersion(config.VersionEndIncluding);
        var endExcl = ParseVersion(config.VersionEndExcluding);

        if (startIncl != null && version < startIncl) return false;
        if (startExcl != null && version <= startExcl) return false;
        if (endIncl != null && version > endIncl) return false;
        if (endExcl != null && version >= endExcl) return false;

        // At least one bound must exist to count as a range hit.
        return startIncl != null || startExcl != null || endIncl != null || endExcl != null;
    }

    // ----- Index ----------------------------------------------------------

    private async Task<Dictionary<string, List<CveConfiguration>>> BuildProductIndexAsync(CancellationToken ct)
    {
        var configs = await _matchManager.Context.Set<CveConfiguration>()
            .Where(c => c.IsVulnerable)
            .ToListAsync(ct);
        return BuildIndex(configs);
    }

    private static Dictionary<string, List<CveConfiguration>> BuildIndex(IEnumerable<CveConfiguration> configs)
    {
        var index = new Dictionary<string, List<CveConfiguration>>(StringComparer.OrdinalIgnoreCase);
        foreach (var config in configs)
        {
            var key = NormalizeProduct(config.Product);
            if (string.IsNullOrEmpty(key))
            {
                continue;
            }
            if (!index.TryGetValue(key, out var list))
            {
                list = new List<CveConfiguration>();
                index[key] = list;
            }
            list.Add(config);
        }
        return index;
    }

    // ----- Parsing helpers ------------------------------------------------

    /// <summary>Normalize a product name to a comparable token (lowercased, noise stripped).</summary>
    internal static string NormalizeProduct(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        // Drop a trailing version from the name, lowercase, split on non-alphanumerics.
        var withoutVersion = VersionRegex.Replace(raw, " ");
        var tokens = Regex.Split(withoutVersion.ToLowerInvariant(), @"[^a-z0-9]+")
            .Where(t => t.Length > 1 && !NoiseTokens.Contains(t))
            .ToList();
        return tokens.Count == 0 ? string.Empty : string.Join("_", tokens);
    }

    /// <summary>Loose product comparison: equality or either-direction containment of tokens.</summary>
    private static bool ProductsMatch(string serviceProduct, string configProduct)
    {
        if (serviceProduct.Equals(configProduct, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        // Token containment (e.g. "apache_http" vs "http_server" share "http").
        return serviceProduct.Contains(configProduct, StringComparison.OrdinalIgnoreCase) ||
               configProduct.Contains(serviceProduct, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Parse a dotted numeric version out of free text; null if none found.</summary>
    internal static Version ParseVersion(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }
        var match = VersionRegex.Match(raw);
        if (!match.Success)
        {
            return null;
        }
        return Version.TryParse(match.Value, out var version) ? version : null;
    }
}
