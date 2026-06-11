namespace Cervantes.IFR.Subdomain;

/// <summary>
/// Configuration for the subdomain enumeration providers (MerkleMap, SecurityTrails).
/// Bound from the "SubdomainConfiguration" section of appsettings.json.
/// </summary>
public interface ISubdomainConfiguration
{
    /// <summary>Master switch for the whole feature (UI button + API + scheduled job).</summary>
    bool Enabled { get; set; }

    /// <summary>MerkleMap API token (sent as a Bearer token).</summary>
    string MerkleMapApiKey { get; set; }

    /// <summary>SecurityTrails API key (sent in the "apikey" header).</summary>
    string SecurityTrailsApiKey { get; set; }

    /// <summary>MerkleMap API base URL (host root, the "/v1/search" path is appended in code).</summary>
    string MerkleMapBaseUrl { get; set; }

    /// <summary>SecurityTrails API base URL (including "/v1").</summary>
    string SecurityTrailsBaseUrl { get; set; }

    /// <summary>When true (and <see cref="Enabled"/>), the recurring background enumeration job runs.</summary>
    bool ScheduledEnabled { get; set; }

    /// <summary>Cron expression for the scheduled enumeration job.</summary>
    string Schedule { get; set; }

    /// <summary>Safety cap on the number of MerkleMap result pages fetched per domain.</summary>
    int MaxMerkleMapPages { get; set; }
}
