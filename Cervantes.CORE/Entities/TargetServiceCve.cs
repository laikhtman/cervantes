using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace Cervantes.CORE.Entities;

/// <summary>
/// Correlation between a target's recorded service and a CVE that affects it.
/// Produced by the CVE exposure matching engine; reviewed/dismissed by users.
/// </summary>
public class TargetServiceCve
{
    /// <summary>
    /// Unique identifier for the match.
    /// </summary>
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid Id { get; set; }

    /// <summary>
    /// The target service (product + version) that matched.
    /// </summary>
    [ForeignKey("TargetServiceId")]
    [JsonIgnore]
    public virtual TargetServices TargetService { get; set; }

    /// <summary>
    /// Id of the matched target service.
    /// </summary>
    [Required]
    public Guid TargetServiceId { get; set; }

    /// <summary>
    /// Owning target (denormalized from the service for cheap grouping/queries).
    /// </summary>
    [ForeignKey("TargetId")]
    [JsonIgnore]
    public virtual Target Target { get; set; }

    /// <summary>
    /// Id of the owning target.
    /// </summary>
    [Required]
    public Guid TargetId { get; set; }

    /// <summary>
    /// The matched CVE.
    /// </summary>
    [ForeignKey("CveId")]
    [JsonIgnore]
    public virtual Cve Cve { get; set; }

    /// <summary>
    /// Id of the matched CVE.
    /// </summary>
    [Required]
    public Guid CveId { get; set; }

    /// <summary>
    /// The specific CVE configuration (affected product/version range) that matched, if any.
    /// </summary>
    [ForeignKey("CveConfigurationId")]
    [JsonIgnore]
    public virtual CveConfiguration CveConfiguration { get; set; }

    /// <summary>
    /// Id of the matched CVE configuration (null for keyword-only matches).
    /// </summary>
    public Guid? CveConfigurationId { get; set; }

    /// <summary>
    /// How the match was made: CpeVersionRange, CpeProductOnly, KeywordFallback.
    /// </summary>
    [StringLength(30)]
    public string MatchType { get; set; }

    /// <summary>
    /// Confidence score in the range 0..1 (higher is more certain).
    /// </summary>
    public double Confidence { get; set; }

    /// <summary>
    /// Normalized product token used for the match (for transparency/debugging).
    /// </summary>
    [StringLength(200)]
    public string MatchedProduct { get; set; }

    /// <summary>
    /// Parsed version used for the match (may be empty for product-only matches).
    /// </summary>
    [StringLength(100)]
    public string MatchedVersion { get; set; }

    /// <summary>
    /// User dismissed this as a false positive; excluded from views and alerts.
    /// </summary>
    public bool IsDismissed { get; set; }

    /// <summary>
    /// User confirmed this match is genuine.
    /// </summary>
    public bool IsValidated { get; set; }

    /// <summary>
    /// An alert has already been raised for this match (prevents duplicate alerts).
    /// </summary>
    public bool AlertSent { get; set; }

    /// <summary>
    /// When the alert was raised.
    /// </summary>
    public DateTime? AlertSentDate { get; set; }

    /// <summary>
    /// Match creation date.
    /// </summary>
    public DateTime CreatedDate { get; set; }

    /// <summary>
    /// Match last-modified date.
    /// </summary>
    public DateTime ModifiedDate { get; set; }

    /// <summary>
    /// User the match is attributed to (the service/target owner).
    /// </summary>
    [ForeignKey("UserId")]
    [JsonIgnore]
    public virtual ApplicationUser User { get; set; }

    /// <summary>
    /// Id of the attributed user.
    /// </summary>
    public string UserId { get; set; }
}
