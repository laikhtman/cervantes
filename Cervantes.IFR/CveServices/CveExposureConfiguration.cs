namespace Cervantes.IFR.CveServices;

/// <inheritdoc />
public class CveExposureConfiguration : ICveExposureConfiguration
{
    public bool Enabled { get; set; }
    public bool ScheduledEnabled { get; set; }
    public string Schedule { get; set; } = "0 4 * * *";
    public double MinConfidenceToAlert { get; set; } = 0.85;
    public bool AlertOnKevAlways { get; set; } = true;
    public string WebhookUrl { get; set; } = string.Empty;
}
