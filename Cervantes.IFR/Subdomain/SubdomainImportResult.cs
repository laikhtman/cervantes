namespace Cervantes.IFR.Subdomain;

/// <summary>Outcome of a discover-and-import run for a single target.</summary>
public enum SubdomainImportStatus
{
    Success,
    Disabled,
    TargetNotFound,
    NotEligible,
    NoDomain
}

/// <summary>Result of enumerating and importing subdomains for one target.</summary>
public class SubdomainImportResult
{
    public SubdomainImportStatus Status { get; set; }

    /// <summary>The domain that was enumerated (host extracted from the source target).</summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>Distinct subdomains returned by the providers.</summary>
    public int Found { get; set; }

    /// <summary>New targets created.</summary>
    public int Created { get; set; }

    /// <summary>Subdomains skipped because a matching target already existed.</summary>
    public int Skipped { get; set; }
}
