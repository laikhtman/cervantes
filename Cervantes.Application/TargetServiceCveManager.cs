using Cervantes.Contracts;
using Cervantes.CORE.Entities;

namespace Cervantes.Application;

/// <summary>
/// Manager for target-service to CVE correlation records.
/// </summary>
public class TargetServiceCveManager : GenericManager<TargetServiceCve>, ITargetServiceCveManager
{
    /// <summary>
    /// TargetServiceCve Manager Constructor
    /// </summary>
    /// <param name="context">data context</param>
    public TargetServiceCveManager(IApplicationDbContext context) : base(context)
    {
    }
}
