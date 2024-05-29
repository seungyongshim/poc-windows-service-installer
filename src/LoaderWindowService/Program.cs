using LoaderWindowService;

Directory.SetCurrentDirectory(AppContext.BaseDirectory);

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddWindowsService();
builder.Services.AddHostedService<WorkerHostedService>();

var app = builder.Build();
app.MapGet("/", () => "ok");

app.Run();


