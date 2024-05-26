
using System.Diagnostics;

namespace LoaderWindowService;

internal class WorkerHostedService
(

) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Process.Start("notepad.exe");
        return Task.CompletedTask;
    }
}
