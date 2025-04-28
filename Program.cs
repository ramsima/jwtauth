using lkjaf;
using lkjaf.Models;
using lkjaf.Service;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Register the JWT service
builder.Services.AddSingleton<IJwtService, JwtService>();

builder.Services.AddScoped<JwtAuthorizeFilter>();


// Configure JWT Authentication to use builtin [Authorize] attribute 
var key = Encoding.ASCII.GetBytes(builder.Configuration["Jwt:SecretKey"]);
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };

    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            context.Token = context.Request.Cookies["AuthToken"];
            return Task.CompletedTask;
        }
    };

    options.Events.OnChallenge = context =>
    {
        context.HandleResponse();
        context.Response.Redirect("/Account/Login");
        return Task.CompletedTask;
    };
});

//Redirect unauthorized (401) to Login page
//builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
//{
//    options.Events.OnChallenge = context =>
//    {
//        context.HandleResponse();
//        context.Response.Redirect("/Account/Login");
//        return Task.CompletedTask;
//    };
//});


builder.Services.AddAuthorization();
builder.Services.AddAuthorization();



builder.Services.AddSingleton<DapperContext>();

//Configure Cookie Authentication
//builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
//        .AddCookie(options =>
//        {
//            options.LoginPath = "/Account/Login";//Redirect if not authenticated
//            options.LogoutPath = "/Account/LogOut";
//            options.AccessDeniedPath = "/Account/AccessDenied"; // Unauthorized Page
//            options.ExpireTimeSpan = TimeSpan.FromMinutes(30);// Cookie expiration
//        });

//builder.Services.AddAuthorization();
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
