// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Authentication;
using Polly;
using Polly.Extensions.Http;
using Polly.Retry;
using Spectre.Console;
using Spectre.Console.Cli;

namespace HaveIBeenPwned.PwnedPasswords.Downloader;

sealed class Statistics
{
    public int CloudflareHits;
    public int CloudflareMisses;
    public int CloudflareRequests;
    public long CloudflareRequestTimeHeaders;
    public long CloudflareRequestTimeTotal;
    public long ElapsedMilliseconds;
    public int HashesDownloaded;
    public double CloudflareHitPercentage => CloudflareHits / (double)CloudflareHits * 100;
    public double CloudflareMissPercentage => CloudflareHits / (double)CloudflareHits * 100;
    public double HashesPerSecond => HashesDownloaded / (ElapsedMilliseconds / 1000.0);
}

sealed class PwnedPasswordsDownloader : AsyncCommand<PwnedPasswordsDownloader.Settings>
{
    readonly AsyncRetryPolicy<HttpResponseMessage> _policy =
        HttpPolicyExtensions.HandleTransientHttpError().RetryAsync(10, OnRequestError);

    static void OnRequestError(DelegateResult<HttpResponseMessage> arg1, int arg2)
    {
        var requestUri = arg1.Result?.RequestMessage?.RequestUri?.ToString() ?? "";
        if (arg1.Exception != null)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Failed request #{arg2} while fetching {requestUri}. Exception message: {arg1.Exception.Message}.[/]");
        }
        else
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Failed attempt #{arg2} fetching {requestUri}. Response contained HTTP Status code {arg1.Result?.StatusCode}.[/]");
        }
    }

    public override async Task<int> ExecuteAsync([NotNull] CommandContext context, [NotNull] Settings settings)
    {
        if (settings.Parallelism < 2)
        {
            settings.Parallelism = Math.Max(Environment.ProcessorCount * 8, 2);
        }

        using var httpClient = InitializeHttpClient(2 * settings.Parallelism);

        var processor = new HashRangeProcessor(httpClient, _policy);


        var processingTask = AnsiConsole.Progress()
            .AutoRefresh(false) // Turn off auto refresh
            .AutoClear(false) // Do not remove the task list when done
            .HideCompleted(false) // Hide tasks as they are completed
            .Columns(
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn())
            .StartAsync(async ctx =>
            {
                if (settings.SingleFile)
                {
                    if (File.Exists(settings.OutputFile))
                    {
                        if (!settings.Overwrite)
                        {
                            AnsiConsole.MarkupLine(
                                $"Output file {settings.OutputFile.EscapeMarkup()}.txt already exists. Use -o if you want to overwrite it.");
                            return;
                        }

                        File.Delete(settings.OutputFile);
                    }
                }
                else
                {
                    if (Directory.Exists(settings.OutputFile))
                    {
                        if (!settings.Overwrite && Directory.EnumerateFiles(settings.OutputFile, "*",
                                new EnumerationOptions { RecurseSubdirectories = true }).Any())
                        {
                            AnsiConsole.MarkupLine(
                                $"Output directory {settings.OutputFile.EscapeMarkup()} already exists and is not empty. Use -o if you want to overwrite files.");
                            return;
                        }
                    }
                    else
                    {
                        Directory.CreateDirectory(settings.OutputFile);
                    }
                }

                var timer = Stopwatch.StartNew();
                var progressTask = ctx.AddTask("[green]Hash ranges downloaded[/]", true, 1024 * 1024);

                try
                {
                    var processTask = processor.ProcessRangesAsync(settings);

                    for (;;)
                    {
                        progressTask.Value = processor.Statistics.HashesDownloaded;
                        ctx.Refresh();

                        var doneTask = await Task.WhenAny(processTask, Task.Delay(100)).ConfigureAwait(false);
                        if (doneTask == processTask)
                        {
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    AnsiConsole.WriteException(ex);
                }

                processor.Statistics.ElapsedMilliseconds = timer.ElapsedMilliseconds;
                progressTask.Value = processor.Statistics.HashesDownloaded;
                ctx.Refresh();
                progressTask.StopTask();
            });

        await processingTask;

        AnsiConsole.MarkupLine(
            $"Finished downloading all hash ranges in {processor.Statistics.ElapsedMilliseconds:N0}ms ({processor.Statistics.HashesPerSecond:N2} hashes per second).");
        AnsiConsole.MarkupLine(
            $"We made {processor.Statistics.CloudflareRequests:N0} Cloudflare requests (avg response time: {(double)processor.Statistics.CloudflareRequestTimeTotal / processor.Statistics.CloudflareRequests:N2}ms). Of those, Cloudflare had already cached {processor.Statistics.CloudflareHits:N0} requests, and made {processor.Statistics.CloudflareMisses:N0} requests to the Have I Been Pwned origin server.");

        return 0;
    }

    static HttpClient InitializeHttpClient(int maxConnections)
    {
        if (AppContext.TryGetSwitch("System.Net.SocketsHttpHandler.Http3Support", out var useHttp3))
        {
            Debug.WriteLine($"HTTP/3 enabled: {useHttp3}");
        }

        HttpClientHandler handler = new()
        {
            SslProtocols = SslProtocols.Tls13 | SslProtocols.Tls12, MaxConnectionsPerServer = maxConnections
        };

        if (handler.SupportsAutomaticDecompression)
        {
            handler.AutomaticDecompression = DecompressionMethods.All;
        }

        HttpClient client = new(handler)
        {
            BaseAddress = new("https://api.pwnedpasswords.com/range/"),
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher
        };

        if (useHttp3)
        {
            client.DefaultRequestVersion = HttpVersion.Version30;
            client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;
        }

        var process = Environment.ProcessPath;
        if (process != null)
        {
            client.DefaultRequestHeaders.UserAgent.Add(new("hibp-downloader",
                FileVersionInfo.GetVersionInfo(process).ProductVersion));
        }

        return client;
    }


    public sealed class Settings : CommandSettings
    {
        [Description(
            "Name of the output. Defaults to pwnedpasswords, which writes the output to pwnedpasswords.txt for single file output, or a directory called pwnedpasswords.")]
        [CommandArgument(0, "[outputFile]")]
        public string OutputFile { get; init; } = "pwnedpasswords";

        [Description(
            "The number of parallel requests to make to Have I Been Pwned to download the hash ranges. If omitted or less than 2, defaults to four times the number of processors on the machine.")]
        [CommandOption("-p||--parallelism")]
        [DefaultValue(0)]
        public int Parallelism { get; set; }

        [Description("When set, overwrite any existing files while writing the results. Defaults to false.")]
        [CommandOption("-o|--overwrite")]
        [DefaultValue(false)]
        public bool Overwrite { get; set; } = false;

        [Description(
            "When set, writes the hash ranges into a single .txt file. Otherwise downloads ranges to individual files into a subfolder.")]
        [CommandOption("-s|--single")]
        [DefaultValue(true)]
        public bool SingleFile { get; set; } = true;
    }
}
