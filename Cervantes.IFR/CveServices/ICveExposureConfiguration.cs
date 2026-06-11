namespace Cervantes.IFR.CveServices;

/// <summary>
/// Configuration for the CVE exposure correlation + alerting feature.
/// Bound from the "CveExposureConfiguration" section of appsettings.json.
/// </summary>
public interface ICveExposureConfiguration
{
    /// <summary>Master switch for the feature (UI, scan API, scheduled job).</summary>
    bool Enabled { get; set; }

    /// <summary>When true (and <see cref="Enabled"/>), the recurring re-scan + alert job runs.</summary>
    bool ScheduledEnabled { get; set; }

    /// <summary>Cron expression for the scheduled job.</summary>
    string Schedule { get; set; }

    /// <summary>Minimum confidence (0..1) for a match to raise an alert.</summary>
    double MinConfidenceToAlert { get; set; }

    /// <summary>Always alert on CISA KEV CVEs regardless of confidence.</summary>
    bool AlertOnKevAlways { get; set; }

    /// <summary>Optional webhook URL alerts are POSTed to.</summary>
    string WebhookUrl { get; set; }
}
