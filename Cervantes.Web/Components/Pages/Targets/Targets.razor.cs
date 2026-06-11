using System.Security.Claims;
using Cervantes.Web.Controllers;
using Microsoft.AspNetCore.Components;
using MudBlazor;
using MudBlazor.Extensions;
using MudBlazor.Extensions.Core;
using MudBlazor.Extensions.Options;
using Task = System.Threading.Tasks.Task;
using WsTarget = Cervantes.Web.Components.Pages.Workspace.Target;

namespace Cervantes.Web.Components.Pages.Targets;

public partial class Targets : ComponentBase
{
    [Inject] ISnackbar Snackbar { get; set; }
    [Inject] private TargetController _targetController { get; set; }
    [Inject] private ProjectController _projectController { get; set; }

    private List<CORE.Entities.Target> model = new List<CORE.Entities.Target>();
    private List<CORE.Entities.Target> seleTargets = new List<CORE.Entities.Target>();
    private List<CORE.Entities.Project> projects = new List<CORE.Entities.Project>();
    private Guid? selectedProject;

    private List<BreadcrumbItem> _items;
    private string searchString = "";

    DialogOptionsEx maxWidthEx = new DialogOptionsEx()
    {
        MaximizeButton = true,
        CloseButton = true,
        FullHeight = true,
        CloseOnEscapeKey = true,
        MaxWidth = MaxWidth.Medium,
        MaxHeight = MaxHeight.False,
        FullWidth = true,
        DragMode = MudDialogDragMode.Simple,
        Animations = new[] { AnimationType.SlideIn },
        Position = DialogPosition.CenterRight,
        DisableSizeMarginY = true,
        DisablePositionMargin = true,
        BackdropClick = false,
        Resizeable = true,
    };

    DialogOptionsEx middleWidthEx = new DialogOptionsEx()
    {
        MaximizeButton = true,
        CloseButton = true,
        FullHeight = false,
        CloseOnEscapeKey = true,
        MaxWidth = MaxWidth.Medium,
        MaxHeight = MaxHeight.False,
        FullWidth = true,
        DragMode = MudDialogDragMode.Simple,
        Animations = new[] { AnimationType.SlideIn },
        Position = DialogPosition.Center,
        DisableSizeMarginY = true,
        DisablePositionMargin = true,
        BackdropClick = false,
        Resizeable = true,
    };

    private ClaimsPrincipal userAth;

    protected override async Task OnInitializedAsync()
    {
        userAth = (await authenticationStateProvider.GetAuthenticationStateAsync()).User;
        _items = new List<BreadcrumbItem>
        {
            new BreadcrumbItem(localizer["home"], href: "/", icon: Icons.Material.Filled.Home),
            new BreadcrumbItem(localizer["targets"], href: null, disabled: true, icon: Icons.Material.Filled.Adjust)
        };
        projects = _projectController.Get().OrderBy(x => x.Name).ToList();
        await Update();
        await base.OnInitializedAsync();
    }

    protected async Task Update()
    {
        model = _targetController.GetTargets().ToList();
    }

    private IEnumerable<CORE.Entities.Target> FilteredModel =>
        selectedProject == null ? model : model.Where(x => x.ProjectId == selectedProject);

    private void OnProjectFilterChanged(Guid? value)
    {
        selectedProject = value;
        seleTargets = new List<CORE.Entities.Target>();
    }

    async Task RowClicked(DataGridRowClickEventArgs<CORE.Entities.Target> args)
    {
        var parameters = new DialogParameters { ["target"] = args.Item };
        IMudExDialogReference<WsTarget.TargetDialog>? dlgReference = await DialogService.ShowEx<WsTarget.TargetDialog>("Simple Dialog", parameters, maxWidthEx);

        var result = await dlgReference.Result;

        if (!result.Canceled)
        {
            await Update();
            StateHasChanged();
        }
    }

    private Func<CORE.Entities.Target, bool> _quickFilter => element =>
    {
        if (string.IsNullOrWhiteSpace(searchString))
            return true;
        if (element.Name?.Contains(searchString, StringComparison.OrdinalIgnoreCase) == true)
            return true;
        if (element.Description?.Contains(searchString, StringComparison.OrdinalIgnoreCase) == true)
            return true;
        if (element.Type.ToString().Contains(searchString, StringComparison.OrdinalIgnoreCase))
            return true;
        if (element.Project?.Name?.Contains(searchString, StringComparison.OrdinalIgnoreCase) == true)
            return true;
        if (element.User?.FullName?.Contains(searchString, StringComparison.OrdinalIgnoreCase) == true)
            return true;
        return false;
    };

    private async Task OpenImportDialog()
    {
        if (selectedProject == null)
        {
            return;
        }

        var parameters = new DialogParameters { ["project"] = selectedProject.Value };
        IMudExDialogReference<WsTarget.ImportDialog>? dlgReference = await DialogService.ShowExAsync<WsTarget.ImportDialog>("Simple Dialog", parameters, middleWidthEx);
        var result = await dlgReference.Result;
        if (!result.Canceled)
        {
            await Update();
            StateHasChanged();
        }
    }

    private async Task OpenDialogCreate()
    {
        if (selectedProject == null)
        {
            return;
        }

        var parameters = new DialogParameters { ["project"] = selectedProject.Value };
        IMudExDialogReference<WsTarget.CreateTargetDialog>? dlgReference = await DialogService.ShowExAsync<WsTarget.CreateTargetDialog>("Simple Dialog", parameters, maxWidthEx);
        var result = await dlgReference.Result;
        if (!result.Canceled)
        {
            await Update();
            StateHasChanged();
        }
    }

    private async Task BtnActions(int id)
    {
        switch (id)
        {
            case 0:
                var parameters = new DialogParameters { ["targets"] = seleTargets };
                IMudExDialogReference<WsTarget.DeleteTargetBulkDialog>? dlgReference = await DialogService.ShowExAsync<WsTarget.DeleteTargetBulkDialog>("Simple Dialog", parameters, middleWidthEx);

                var result = await dlgReference.Result;

                if (!result.Canceled)
                {
                    seleTargets = new List<CORE.Entities.Target>();
                    await Update();
                    StateHasChanged();
                }
                break;
        }
    }

    void SelectedItemsChanged(HashSet<CORE.Entities.Target> items)
    {
        seleTargets = items.ToList();
    }
}
