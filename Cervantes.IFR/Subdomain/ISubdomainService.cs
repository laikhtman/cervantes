namespace Cervantes.IFR.Subdomain;

/// <summary>
/// Enumerates subdomains for domain-style targets via MerkleMap / SecurityTrails
/// and imports the results as new targets.
/// </summary>
public interface ISubdomainService
{
    /// <summary>True when the feature is enabled and at least one provider key is configured.</summary>
    bool Enabled { get; }

    /// <summary>
    /// Returns the distinct subdomains of <paramref name="domain"/> reported by the configured
    /// providers. A provider failure is logged and skipped; the other still contributes results.
    /// </summary>
    Task<IReadOnlyList<string>> EnumerateAsync(string domain, CancellationToken ct = default);

    /// <summary>
    /// Enumerates subdomains for the given target's domain and creates each new one as a
    /// Hostname target in the same project, deduped against existing target names.
    /// </summary>
    Task<SubdomainImportResult> DiscoverAndImportAsync(Guid targetId, string userId, CancellationToken ct = default);

    /// <summary>
    /// Background job body: runs <see cref="DiscoverAndImportAsync"/> for every eligible
    /// (URL/Hostname) target currently in the system.
    /// </summary>
    Task RunScheduledAsync(CancellationToken ct = default);
}
