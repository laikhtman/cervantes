using System.Text.RegularExpressions;
using Cervantes.Contracts;
using Cervantes.CORE.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Task = System.Threading.Tasks.Task;

namespace Cervantes.IFR.CveServices;

/// <summary>
/// Correlates target services against CVE CPE configurations with a tiered, scored match that
/// uses both the CPE product and vendor, plus a small alias map to bridge common banner/CPE
/// naming differences (e.g. "Apache httpd" vs vendor "apache" / product "http_server").
/// </summary>
public class CveMatchingService : ICveMatchingService
{
    private readonly ITargetServicesManager _targetServicesManager;
    private readonly ITargetServiceCveManager _matchManager;
    private readonly ICveManager _cveManager;
    private readonly ILogger<CveMatchingService> _logger;

    private static readonly Regex VersionRegex = new(@"\d+(\.\d+)+", RegexOptions.Compiled);

    // Tokens too generic to identify a product on their own. A product match requires at least
    // one shared NON-generic token, so "http_server" and "sql_server" don't match on "server".
    private static readonly HashSet<string> GenericTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "server", "service", "services", "system", "software", "framework", "library", "module",
        "the", "for", "and", "project", "edition", "community", "professional", "enterprise",
        "standard", "app", "application", "daemon", "client", "tool", "tools"
    };

    // Service-banner token -> canonical CPE product tokens. Bridges the most common mismatches
    // between scanner banners and NVD CPE product names.
    private static readonly Dictionary<string, string[]> ProductAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["httpd"] = new[] { "http", "server" },
        ["apache2"] = new[] { "http", "server" },
        ["iis"] = new[] { "internet", "information", "services" },
        ["postgres"] = new[] { "postgresql" },
        ["mysqld"] = new[] { "mysql" },
        ["nodejs"] = new[] { "node", "js" },
        ["bind9"] = new[] { "bind" },
        ["exim4"] = new[] { "exim" },
        ["named"] = new[] { "bind" }
    };

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

        var index = await BuildFullIndexAsync(ct);
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

        var index = await BuildFullIndexAsync(ct);
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

        var index = await BuildFullIndexAsync(ct);
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
            var newOnes = await MatchOneServiceAsync(service, index, userId, result, ct);
            created.AddRange(newOnes);
        }
        await _matchManager.Context.SaveChangesAsync();
        return created;
    }

    // ----- Core matching --------------------------------------------------

    /// <summary>
    /// Scores a single service against the inverted token index and upserts matches.
    /// Returns the newly-created records (for alerting).
    /// </summary>
    private async Task<List<TargetServiceCve>> MatchOneServiceAsync(
        TargetServices service,
        Dictionary<string, List<ConfigEntry>> index,
        string userId,
        CveExposureScanResult result,
        CancellationToken ct)
    {
        result.ServicesScanned++;
        var created = new List<TargetServiceCve>();

        var serviceTokens = TokenSet(service.Name);
        if (serviceTokens.Count == 0)
        {
            return created;
        }
        var version = ParseVersion(service.Version) ?? ParseVersion(service.Name);

        // Gather candidate configs via the inverted index (non-generic tokens only).
        var candidates = new HashSet<ConfigEntry>();
        foreach (var token in serviceTokens)
        {
            if (GenericTokens.Contains(token))
            {
                continue;
            }
            if (index.TryGetValue(token, out var entries))
            {
                foreach (var e in entries)
                {
                    candidates.Add(e);
                }
            }
        }

        // Best match per CVE for this service.
        var best = new Dictionary<Guid, (ConfigEntry entry, double confidence, string matchType)>();
        foreach (var entry in candidates)
        {
            var (confidence, matchType) = Score(entry, serviceTokens, version);
            if (confidence <= 0)
            {
                continue;
            }
            var cveId = entry.Config.CveId;
            if (!best.TryGetValue(cveId, out var existing) || confidence > existing.confidence)
            {
                best[cveId] = (entry, confidence, matchType);
            }
        }

        foreach (var (cveId, match) in best)
        {
            result.Matches++;
            var existing = await _matchManager.GetAll()
                .FirstOrDefaultAsync(x => x.TargetServiceId == service.Id && x.CveId == cveId, ct);

            var matchedProduct = BuildMatchedProduct(match.entry.Config);
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
                    existing.CveConfigurationId = match.entry.Config.Id;
                    existing.MatchedProduct = matchedProduct;
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
                CveConfigurationId = match.entry.Config.Id,
                MatchType = match.matchType,
                Confidence = match.confidence,
                MatchedProduct = matchedProduct,
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
    /// Scores a candidate config against a service's token set and parsed version.
    /// Returns (confidence, matchType); confidence 0 means no match.
    /// </summary>
    private static (double confidence, string matchType) Score(ConfigEntry entry, HashSet<string> serviceTokens, Version version)
    {
        var verdict = VersionVerdict(entry.Config, version);
        if (verdict == VerdictKind.Reject)
        {
            return (0, string.Empty);
        }

        var productSignal = entry.ProductTokens.Any(t => !GenericTokens.Contains(t) && serviceTokens.Contains(t));
        var vendorMatched = entry.VendorTokens.Any(serviceTokens.Contains);

        if (productSignal)
        {
            double baseScore;
            string type;
            switch (verdict)
            {
                case VerdictKind.Exact: baseScore = 0.95; type = "CpeVersionRange"; break;
                case VerdictKind.Range: baseScore = 0.85; type = "CpeVersionRange"; break;
                default: baseScore = 0.50; type = "CpeProductOnly"; break;
            }
            if (vendorMatched)
            {
                baseScore = Math.Min(0.98, baseScore + 0.03);
            }
            return (baseScore, type);
        }

        if (vendorMatched)
        {
            // Vendor matched but product did not — a weaker signal.
            var baseScore = verdict switch
            {
                VerdictKind.Exact => 0.65,
                VerdictKind.Range => 0.55,
                _ => 0.30
            };
            return (baseScore, "CpeVendorOnly");
        }

        return (0, string.Empty);
    }

    private enum VerdictKind { Exact, Range, Unknown, Reject }

    /// <summary>
    /// Compares a service version against a config's version/range. Returns Reject when both sides
    /// have comparable version info that does NOT match (avoids flagging patched versions).
    /// </summary>
    private static VerdictKind VersionVerdict(CveConfiguration config, Version version)
    {
        var configVersion = ParseVersion(config.Version);
        var startIncl = ParseVersion(config.VersionStartIncluding);
        var startExcl = ParseVersion(config.VersionStartExcluding);
        var endIncl = ParseVersion(config.VersionEndIncluding);
        var endExcl = ParseVersion(config.VersionEndExcluding);
        var anyBound = startIncl != null || startExcl != null || endIncl != null || endExcl != null;

        if (version != null && configVersion != null && version == configVersion)
        {
            return VerdictKind.Exact;
        }
        if (version != null && anyBound && InRange(version, startIncl, startExcl, endIncl, endExcl))
        {
            return VerdictKind.Range;
        }
        if (version == null || (configVersion == null && !anyBound))
        {
            return VerdictKind.Unknown;
        }
        return VerdictKind.Reject;
    }

    private static bool InRange(Version v, Version startIncl, Version startExcl, Version endIncl, Version endExcl)
    {
        if (startIncl != null && v < startIncl) return false;
        if (startExcl != null && v <= startExcl) return false;
        if (endIncl != null && v > endIncl) return false;
        if (endExcl != null && v >= endExcl) return false;
        return true;
    }

    // ----- Index ----------------------------------------------------------

    private async Task<Dictionary<string, List<ConfigEntry>>> BuildFullIndexAsync(CancellationToken ct)
    {
        var configs = await _matchManager.Context.Set<CveConfiguration>()
            .Where(c => c.IsVulnerable)
            .ToListAsync(ct);
        return BuildIndex(configs);
    }

    /// <summary>
    /// Inverted index: non-generic product/vendor token -> the configs that carry it.
    /// </summary>
    private static Dictionary<string, List<ConfigEntry>> BuildIndex(IEnumerable<CveConfiguration> configs)
    {
        var index = new Dictionary<string, List<ConfigEntry>>(StringComparer.OrdinalIgnoreCase);
        foreach (var config in configs)
        {
            var productTokens = TokenSet(config.Product);
            var vendorTokens = TokenSet(config.Vendor);
            if (productTokens.Count == 0 && vendorTokens.Count == 0)
            {
                continue;
            }

            var entry = new ConfigEntry { Config = config, ProductTokens = productTokens, VendorTokens = vendorTokens };

            var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in productTokens) keys.Add(t);
            foreach (var t in vendorTokens) keys.Add(t);

            foreach (var key in keys)
            {
                if (GenericTokens.Contains(key))
                {
                    continue;
                }
                if (!index.TryGetValue(key, out var list))
                {
                    list = new List<ConfigEntry>();
                    index[key] = list;
                }
                list.Add(entry);
            }
        }
        return index;
    }

    // ----- Parsing helpers ------------------------------------------------

    /// <summary>
    /// Tokenize a product/vendor/banner string into normalized tokens, expanding known aliases.
    /// Version numbers are stripped; tokens of length 1 are dropped.
    /// </summary>
    internal static HashSet<string> TokenSet(string raw)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return set;
        }

        var withoutVersion = VersionRegex.Replace(raw, " ");
        var normalized = Regex.Replace(withoutVersion.ToLowerInvariant(), @"[^a-z0-9]+", "_").Trim('_');
        foreach (var token in normalized.Split('_', StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.Length <= 1)
            {
                continue;
            }
            set.Add(token);
            if (ProductAliases.TryGetValue(token, out var aliases))
            {
                foreach (var alias in aliases)
                {
                    set.Add(alias);
                }
            }
        }
        return set;
    }

    private static string BuildMatchedProduct(CveConfiguration config)
    {
        var vendor = config.Vendor ?? string.Empty;
        var product = config.Product ?? string.Empty;
        var combined = string.IsNullOrEmpty(vendor) ? product : $"{vendor}/{product}";
        return combined.Length > 200 ? combined.Substring(0, 200) : combined;
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

    private sealed class ConfigEntry
    {
        public CveConfiguration Config { get; init; }
        public HashSet<string> ProductTokens { get; init; }
        public HashSet<string> VendorTokens { get; init; }
    }
}
