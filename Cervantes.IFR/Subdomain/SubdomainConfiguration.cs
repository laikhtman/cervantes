namespace Cervantes.IFR.Subdomain;

/// <inheritdoc />
public class SubdomainConfiguration : ISubdomainConfiguration
{
    public bool Enabled { get; set; }
    public string MerkleMapApiKey { get; set; } = string.Empty;
    public string SecurityTrailsApiKey { get; set; } = string.Empty;
    public string MerkleMapBaseUrl { get; set; } = "https://api.merklemap.com";
    public string SecurityTrailsBaseUrl { get; set; } = "https://api.securitytrails.com/v1";
    public bool ScheduledEnabled { get; set; }
    public string Schedule { get; set; } = "0 3 * * *";
    public int MaxMerkleMapPages { get; set; } = 20;
}
