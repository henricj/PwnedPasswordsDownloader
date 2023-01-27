using System.Buffers;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipelines;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Text;
using System.Threading.Channels;
using HaveIBeenPwned.PwnedPasswords;
using Microsoft.Win32.SafeHandles;
using Polly;
using Polly.Extensions.Http;
using Polly.Retry;
using Spectre.Console;
using Spectre.Console.Cli;

CommandApp<PwnedPasswordsDownloader> app = new();

app.Configure(config => config.PropagateExceptions());

try
{
    return await app.RunAsync(args).ConfigureAwait(false);
}
catch (Exception ex)
{
    AnsiConsole.WriteException(ex, ExceptionFormats.ShortenEverything);
    return -99;
}

sealed class Statistics
{
    public int CloudflareHits;
    public int CloudflareMisses;
    public int CloudflareRequests;
    public long CloudflareRequestTimeTotal;
    public long ElapsedMilliseconds;
    public int HashesDownloaded;
    public double CloudflareHitPercentage => CloudflareHits / (double)CloudflareHits * 100;
    public double CloudflareMissPercentage => CloudflareHits / (double)CloudflareHits * 100;
    public double HashesPerSecond => HashesDownloaded / (ElapsedMilliseconds / 1000.0);
}

sealed class PwnedPasswordsDownloader : Command<PwnedPasswordsDownloader.Settings>
{
    static readonly StreamPipeReaderOptions s_singleFilePipeReaderOptions =
        new(bufferSize: 64 * 1024, minimumReadSize: 4096, leaveOpen: true);

    static readonly StreamPipeWriterOptions s_singleFilePipeWriterOptions = new(minimumBufferSize: 64 * 1024, leaveOpen: true);

    static readonly byte[] s_eol = Encoding.ASCII.GetBytes(Environment.NewLine);

    //internal static Encoding s_encoding = Encoding.UTF8;
    readonly HttpClient _httpClient = InitializeHttpClient();

    readonly AsyncRetryPolicy<HttpResponseMessage> _policy =
        HttpPolicyExtensions.HandleTransientHttpError().RetryAsync(10, OnRequestError);

    readonly Statistics _statistics = new();
    int _hashesInProgress;

    static void OnRequestError(DelegateResult<HttpResponseMessage> arg1, int arg2)
    {
        string requestUri = arg1.Result?.RequestMessage?.RequestUri?.ToString() ?? "";
        if (arg1.Exception != null)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Failed request #{arg2} while fetching {requestUri}. Exception message: {arg1.Exception.Message}.[/]");
        }
        else
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Failed attempt #{arg2} fetching {requestUri}. Response contained HTTP Status code {arg1?.Result?.StatusCode}.[/]");
        }
    }

    public override int Execute([NotNull] CommandContext context, [NotNull] Settings settings)
    {
        if (settings.Parallelism < 2)
        {
            settings.Parallelism = Math.Max(Environment.ProcessorCount * 8, 2);
        }

        Task processingTask = AnsiConsole.Progress()
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
                        if (!settings.Overwrite && Directory.EnumerateFiles(settings.OutputFile).Any())
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


                Stopwatch timer = Stopwatch.StartNew();
                ProgressTask progressTask = ctx.AddTask("[green]Hash ranges downloaded[/]", true, 1024 * 1024);

                try
                {
                    Task processTask = ProcessRangesAsync(settings);

                    for (; ; )
                    {
                        progressTask.Value = _statistics.HashesDownloaded;
                        ctx.Refresh();

                        Task doneTask = await Task.WhenAny(processTask, Task.Delay(100)).ConfigureAwait(false);
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

                _statistics.ElapsedMilliseconds = timer.ElapsedMilliseconds;
                progressTask.Value = _statistics.HashesDownloaded;
                ctx.Refresh();
                progressTask.StopTask();
            });

        processingTask.Wait();
        AnsiConsole.MarkupLine(
            $"Finished downloading all hash ranges in {_statistics.ElapsedMilliseconds:N0}ms ({_statistics.HashesPerSecond:N2} hashes per second).");
        AnsiConsole.MarkupLine(
            $"We made {_statistics.CloudflareRequests:N0} Cloudflare requests (avg response time: {(double)_statistics.CloudflareRequestTimeTotal / _statistics.CloudflareRequests:N2}ms). Of those, Cloudflare had already cached {_statistics.CloudflareHits:N0} requests, and made {_statistics.CloudflareMisses:N0} requests to the Have I Been Pwned origin server.");

        return 0;
    }

    static HttpClient InitializeHttpClient()
    {
        HttpClientHandler handler = new() { SslProtocols = SslProtocols.Tls13 | SslProtocols.Tls12 };

        if (handler.SupportsAutomaticDecompression)
        {
            handler.AutomaticDecompression = DecompressionMethods.All;
        }

        HttpClient client = new(handler)
        {
            BaseAddress = new Uri("https://api.pwnedpasswords.com/range/"),
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher
        };
        string? process = Environment.ProcessPath;
        if (process != null)
        {
            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("hibp-downloader",
                FileVersionInfo.GetVersionInfo(process).ProductVersion));
        }

        return client;
    }

    async Task<Stream> GetPwnedPasswordsRangeFromWeb(int i)
    {
        Stopwatch cloudflareTimer = Stopwatch.StartNew();
        string requestUri = GetHashRange(i);
        HttpResponseMessage response = await _policy.ExecuteAsync(() =>
        {
            using HttpRequestMessage request = new(HttpMethod.Get, requestUri);
            return _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        }).ConfigureAwait(false);
        Stream content = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        Interlocked.Add(ref _statistics.CloudflareRequestTimeTotal, cloudflareTimer.ElapsedMilliseconds);
        Interlocked.Increment(ref _statistics.CloudflareRequests);
        if (response.Headers.TryGetValues("CF-Cache-Status", out IEnumerable<string>? values) && values != null)
        {
            switch (values.FirstOrDefault())
            {
                case "HIT":
                    Interlocked.Increment(ref _statistics.CloudflareHits);
                    break;
                default:
                    Interlocked.Increment(ref _statistics.CloudflareMisses);
                    break;
            }
        }

        return content;
    }

    string GetHashRange(int i)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, i);
        return Convert.ToHexString(bytes)[3..];
    }

    async Task ProcessRangesAsync(Settings settings)
    {
        if (settings.SingleFile)
        {
            Channel<Task<Stream>> downloadTasks = Channel.CreateBounded<Task<Stream>>(
                new BoundedChannelOptions(settings.Parallelism)
                {
                    SingleReader = true,
                    SingleWriter = true,
                    AllowSynchronousContinuations = true
                });

            await using FileStream file = File.Open($"{settings.OutputFile}.txt",
                new FileStreamOptions
                {
                    Access = FileAccess.Write,
                    BufferSize = 128 * 1024,
                    Mode = FileMode.Create,
                    Options = FileOptions.Asynchronous,
                    Share = FileShare.None
                });
            //await using StreamWriter writer = new(file);
            PipeWriter writer = PipeWriter.Create(file, s_singleFilePipeWriterOptions);

            Task producerTask = StartDownloads(downloadTasks.Writer);

            await foreach (Task<Stream> item in downloadTasks.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                string prefix = GetHashRange(_statistics.HashesDownloaded++);

                await using Stream inputStream = await item.ConfigureAwait(false);

                PipeReader reader = PipeReader.Create(inputStream, s_singleFilePipeReaderOptions);

                await WriteSingleFileAsync(reader, writer, prefix).ConfigureAwait(false);

                await reader.CompleteAsync();
            }

            await writer.FlushAsync().ConfigureAwait(false);
            await writer.CompleteAsync().ConfigureAwait(false);

            await producerTask.ConfigureAwait(false);
        }
        else
        {
            Task[] downloadTasks = new Task[settings.Parallelism];
            for (int i = 0; i < downloadTasks.Length; i++)
            {
                downloadTasks[i] = DownloadRangeToFile(settings.OutputFile);
            }

            await Task.WhenAll(downloadTasks).ConfigureAwait(false);
        }
    }

    static async ValueTask WriteSingleFileAsync(PipeReader reader, PipeWriter writer, string prefix)
    {
        var prefixBytes = Encoding.ASCII.GetBytes(prefix);

        for (; ; )
        {
            if (!reader.TryRead(out ReadResult result))
            {
                result = await reader.ReadAsync().ConfigureAwait(false);
            }

            if (result.IsCompleted)
            {
                break;
            }

            ReadOnlySequence<byte> buffer = result.Buffer;

            var position = ParseBuffer(ref buffer, writer, prefixBytes);

            reader.AdvanceTo(position, buffer.End);

            await writer.FlushAsync().ConfigureAwait(false);
        }

        static void WriteLine(ReadOnlySpan<byte> readOnlySpan, ReadOnlySpan<byte> prefix, PipeWriter pipeWriter)
        {
            if (readOnlySpan.Length <= 8) // A valid line can't be less than 8 bytes.
            {
                return;
            }

            int length = prefix.Length + readOnlySpan.Length + s_eol.Length;

            Span<byte> output = pipeWriter.GetSpan(length);

            prefix.CopyTo(output);
            output = output[prefix.Length..];

            readOnlySpan.CopyTo(output);
            output = output[readOnlySpan.Length..];

            s_eol.CopyTo(output);

            pipeWriter.Advance(length);
        }

        static SequencePosition ParseBuffer(ref ReadOnlySequence<byte> buffer, PipeWriter writer, ReadOnlySpan<byte> prefix)
        {
            SequenceReader<byte> sequenceReader = new(buffer);

            while (!sequenceReader.End)
            {
                // Skip any newline characters
                sequenceReader.AdvancePastAny(0x0a, 0x0d);

                if (!sequenceReader.TryReadTo(out ReadOnlySpan<byte> line, 0x0a, false))
                {
                    break;
                }

                WriteLine(line, prefix, writer);
            }

            return sequenceReader.Position;
        }
    }

    async Task StartDownloads(ChannelWriter<Task<Stream>> channelWriter)
    {
        try
        {
            for (int i = 0; i < 1024 * 1024; i++)
            {
                await channelWriter.WriteAsync(GetPwnedPasswordsRangeFromWeb(i));
            }

            channelWriter.TryComplete();
        }
        catch (Exception e)
        {
            channelWriter.TryComplete(e);
        }
    }

    async Task DownloadRangeToFile(string outputDirectory)
    {
        int nextHash = Interlocked.Increment(ref _hashesInProgress);
        int currentHash = nextHash - 1;
        while (currentHash < 1024 * 1024)
        {
            await using Stream stream = await GetPwnedPasswordsRangeFromWeb(currentHash).ConfigureAwait(false);
            using SafeFileHandle handle = File.OpenHandle(Path.Combine(outputDirectory, $"{GetHashRange(currentHash)}.txt"),
                FileMode.Create, FileAccess.Write, FileShare.None, FileOptions.Asynchronous);
            await handle.CopyFrom(stream).ConfigureAwait(false);
            Interlocked.Increment(ref _statistics.HashesDownloaded);
            nextHash = Interlocked.Increment(ref _hashesInProgress);
            currentHash = nextHash - 1;
        }
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
