using Cervantes.CORE.Entities;

namespace Cervantes.IFR.CveServices;

/// <summary>
/// Result of a CVE exposure scan.
/// </summary>
public class CveExposureScanResult
{
    public int ServicesScanned { get; set; }
    public int Matches { get; set; }
    public int Created { get; set; }
    public int Updated { get; set; }
    public int Skipped { get; set; }
}

/// <summary>
/// Correlates recorded target services (product + version) against the CVE database's
/// CPE configurations, recording matches as <see cref="TargetServiceCve"/> records.
/// </summary>
public interface ICveMatchingService
{
    /// <summary>Correlate a single target service against the CVE database.</summary>
    Task<CveExposureScanResult> MatchServiceAsync(Guid targetServiceId, string userId, CancellationToken ct = default);

    /// <summary>Correlate every service belonging to a target.</summary>
    Task<CveExposureScanResult> MatchTargetAsync(Guid targetId, string userId, CancellationToken ct = default);

    /// <summary>
    /// Correlate all services (optionally limited to a single project) against the CVE database.
    /// </summary>
    Task<CveExposureScanResult> MatchAllAsync(Guid? projectId, string userId, CancellationToken ct = default);

    /// <summary>
    /// Reverse direction: match the given newly-synced CVEs against existing services and return
    /// the matches that are newly created and eligible to alert on.
    /// </summary>
    Task<IReadOnlyList<TargetServiceCve>> MatchNewCvesAsync(IEnumerable<Guid> cveIds, string userId, CancellationToken ct = default);
}
