
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;

namespace LoaderWindowService;

internal class WorkerHostedService
(

) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var applicationName = "cmd.exe";

            // launch the application
            var ret = ApplicationLoader.StartProcessAndBypassUAC(applicationName, out var procInfo);

            Console.WriteLine(ret);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }

        return Task.CompletedTask;
    }
}
