using System.Diagnostics;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using SharePassword.Models;
using SharePassword.Services;

namespace SharePassword.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        var exceptionFeature = HttpContext.Features.Get<IExceptionHandlerPathFeature>();
        var databaseException = exceptionFeature?.Error as DatabaseOperationException;

        return View(new ErrorViewModel
        {
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
            Title = databaseException is null ? "Error" : "Database Unavailable",
            Message = databaseException?.UserMessage ?? "An error occurred while processing your request.",
            IsDatabaseError = databaseException is not null
        });
    }
}
