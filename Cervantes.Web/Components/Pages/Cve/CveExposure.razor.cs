using System.Security.Claims;
using Cervantes.CORE.ViewModel;
using Cervantes.Web.Controllers;
using Microsoft.AspNetCore.Components;
using MudBlazor;
using Task = System.Threading.Tasks.Task;

namespace Cervantes.Web.Components.Pages.Cve;

public partial class CveExposure : ComponentBase
{
    [Inject] ISnackbar Snackbar { get; set; }
    [Inject] private TargetController _targetController { get; set; }
    [Inject] private ProjectController _projectController { get; set; }

    private List<CveExposureViewModel> model = new();
    private List<CORE.Entities.Project> projects = new();
    private List<BreadcrumbItem> _items;

    private ClaimsPrincipal userAth;
    private bool exposureEnabled;
    private bool loading;
    private bool scanning;

    private string searchString = "";
    private Guid? selectedProject;
    private string severityFilter;
    private bool kevOnly;

    protected override async Task OnInitializedAsync()
    {
        userAth = (await authenticationStateProvider.GetAuthenticationStateAsync()).User;
        _items = new List<BreadcrumbItem>
        {
            new BreadcrumbItem(localizer["home"], href: "/", icon: Icons.Material.Filled.Home),
            new BreadcrumbItem(localizer["cveExposure"], href: null, disabled: true, icon: Icons.Material.Filled.Security)
        };
        exposureEnabled = _targetController.IsCveExposureEnabled();
        projects = _projectController.Get().OrderBy(x => x.Name).ToList();
        await Update();
        await base.OnInitializedAsync();
    }

    private async Task Update()
    {
        loading = true;
        try
        {
            model = _targetController.GetAllCveExposureList();
        }
        catch (Exception)
        {
            Snackbar.Add(localizer["cveExposureError"], Severity.Error);
        }
        finally
        {
            loading = false;
        }
    }

    private IEnumerable<CveExposureViewModel> FilteredModel =>
        model.Where(x =>
            (selectedProject == null || x.ProjectId == selectedProject) &&
            (string.IsNullOrEmpty(severityFilter) ||
             string.Equals(x.Severity, severityFilter, StringComparison.OrdinalIgnoreCase)) &&
            (!kevOnly || x.IsKnownExploited));

    private void OnProjectChanged(Guid? value) => selectedProject = value;

    private async Task ScanAll()
    {
        scanning = true;
        StateHasChanged();
        try
        {
            var result = await _targetController.RunAllCveExposureScan(selectedProject);
            Snackbar.Add(
                $"{localizer["cveExposureScanComplete"]} — {result.ServicesScanned} services, {result.Created} new, {result.Updated} updated",
                Severity.Success);
            await Update();
        }
        catch (Exception)
        {
            Snackbar.Add(localizer["cveExposureError"], Severity.Error);
        }
        finally
        {
            scanning = false;
            StateHasChanged();
        }
    }

    private async Task Dismiss(CveExposureViewModel item)
    {
        var ok = await _targetController.DismissCveExposureMatch(item.Id);
        if (ok)
        {
            model.Remove(item);
            Snackbar.Add(localizer["cveExposureDismissed"], Severity.Success);
            StateHasChanged();
        }
    }

    private Func<CveExposureViewModel, bool> _quickFilter => element =>
    {
        if (string.IsNullOrWhiteSpace(searchString))
            return true;
        if (element.CveIdentifier?.Contains(searchString, StringComparison.OrdinalIgnoreCase) == true)
            return true;
        if (element.TargetName?.Contains(searchString, StringComparison.OrdinalIgnoreCase) == true)
            return true;
        if (element.ServiceName?.Contains(searchString, StringComparison.OrdinalIgnoreCase) == true)
            return true;
        if (element.CveTitle?.Contains(searchString, StringComparison.OrdinalIgnoreCase) == true)
            return true;
        return false;
    };

    private static Color SeverityColor(string severity) => severity?.ToUpperInvariant() switch
    {
        "CRITICAL" => Color.Error,
        "HIGH" => Color.Warning,
        "MEDIUM" => Color.Info,
        "LOW" => Color.Success,
        _ => Color.Default
    };

    private static Color ConfidenceColor(double confidence) => confidence switch
    {
        >= 0.85 => Color.Success,
        >= 0.5 => Color.Warning,
        _ => Color.Default
    };
}
