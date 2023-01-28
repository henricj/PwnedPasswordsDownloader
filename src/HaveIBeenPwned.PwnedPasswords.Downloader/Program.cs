using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Text;
using HaveIBeenPwned.PwnedPasswords.Downloader;
using Spectre.Console;
using Spectre.Console.Cli;

CommandApp<PwnedPasswordsDownloader> app = new();

app.Configure(config => config.PropagateExceptions());

try
{
#if DEBUG
    // Keep the listener around while you want the logging to continue, dispose it after.
    //using var listener = new HttpEventListener();
#endif

    return await app.RunAsync(args).ConfigureAwait(false);
}
catch (Exception ex)
{
    AnsiConsole.WriteException(ex, ExceptionFormats.ShortenEverything);
    return -99;
}


/// <summary>
/// Echo HttpClient's log messages to Debug.WriteLine(). 
/// https://github.com/dotnet/runtime/issues/64977#issuecomment-1032485432
/// </summary>
sealed class HttpEventListener : EventListener
{
    protected override void OnEventSourceCreated(EventSource eventSource)
    {
        // Allow internal HTTP logging
        if (eventSource.Name == "Private.InternalDiagnostics.System.Net.Http")
        {
            EnableEvents(eventSource, EventLevel.LogAlways);
        }
    }

    protected override void OnEventWritten(EventWrittenEventArgs eventData)
    {
        // Log whatever other properties you want, this is just an example
        var sb = new StringBuilder().Append($"{eventData.TimeStamp:HH:mm:ss.fffffff}[{eventData.EventName}] ");
        for (var i = 0; i < eventData.Payload?.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(", ");
            }

            sb.Append(eventData.PayloadNames?[i]).Append(": ").Append(eventData.Payload[i]);
        }

        try
        {
            Debug.WriteLine(sb.ToString());
        }
        catch
        { }
    }
}
