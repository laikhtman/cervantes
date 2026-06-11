using Cervantes.CORE.Entities;
using Task = System.Threading.Tasks.Task;

namespace Cervantes.CORE.ViewModel;

public class SearchViewModel
{
    public IEnumerable<ApplicationUser> Users { get; set; } = new List<ApplicationUser>();
    public IEnumerable<Client> Clients { get; set; } = new List<Client>();
    public IEnumerable<Project> Projects { get; set; } = new List<Project>();
    public IEnumerable<Document> Documents { get; set; } = new List<Document>();
    public IEnumerable<Report> Reports { get; set; } = new List<Report>();
    public IEnumerable<Target> Targets { get; set; } = new List<Target>();
    public IEnumerable<TargetServices> TargetServices { get; set; } = new List<TargetServices>();
    public IEnumerable<CORE.Entities.Task> Tasks { get; set; } = new List<CORE.Entities.Task>();
    public IEnumerable<Vault> Vaults { get; set; } = new List<Vault>();
    public IEnumerable<VulnCategory> VulnCategories { get; set; } = new List<VulnCategory>();
    public IEnumerable<Vuln> Vulns { get; set; } = new List<Vuln>();

    public bool HasResults =>
        Users.Any() || Clients.Any() || Projects.Any() || Documents.Any() || Reports.Any() ||
        Targets.Any() || TargetServices.Any() || Tasks.Any() || Vaults.Any() ||
        VulnCategories.Any() || Vulns.Any();
}
