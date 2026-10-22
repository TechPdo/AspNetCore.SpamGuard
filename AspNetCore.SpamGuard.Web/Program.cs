using AspNetCore.SpamGuard;
using AspNetCore.SpamGuard.Web.CustomSpamRules;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

// Binds the "SpamGuard" section. Keep secrets (RecaptchaSecretKey) in user-secrets or environment variables.
builder.Services
    .AddSpamGuard(builder.Configuration.GetSection(SpamGuardOptions.SectionName))
    .AddSpamRule<ExcessiveCapsRule>();

// Behind a reverse proxy, SpamGuard needs the real client IP for rate limiting and StopForumSpam lookups.
// Configure KnownProxies / KnownNetworks for your environment; by default only loopback proxies are trusted.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();
