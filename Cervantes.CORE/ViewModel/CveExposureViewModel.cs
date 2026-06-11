using System;

namespace Cervantes.CORE.ViewModel;

/// <summary>
/// Flattened view of a target-service to CVE correlation, for grids and APIs.
/// </summary>
public class CveExposureViewModel
{
    public Guid Id { get; set; }

    public Guid TargetId { get; set; }
    public string TargetName { get; set; }
    public Guid? ProjectId { get; set; }
    public string ProjectName { get; set; }

    public Guid TargetServiceId { get; set; }
    public string ServiceName { get; set; }
    public int ServicePort { get; set; }
    public string ServiceVersion { get; set; }

    public Guid CveId { get; set; }
    public string CveIdentifier { get; set; }
    public string CveTitle { get; set; }
    public string Severity { get; set; }
    public double? CvssScore { get; set; }
    public double? EpssScore { get; set; }
    public bool IsKnownExploited { get; set; }

    public string MatchType { get; set; }
    public double Confidence { get; set; }
    public string MatchedProduct { get; set; }
    public string MatchedVersion { get; set; }

    public bool IsDismissed { get; set; }
    public bool IsValidated { get; set; }
    public DateTime CreatedDate { get; set; }
}
