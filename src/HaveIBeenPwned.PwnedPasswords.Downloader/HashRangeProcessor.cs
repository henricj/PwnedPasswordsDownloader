// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Threading.Channels;
using Polly;
using Polly.Retry;

namespace HaveIBeenPwned.PwnedPasswords.Downloader;

sealed partial class HashRangeProcessor : IDisposable
{
    readonly CancellationTokenSource _cancellationTokenSource = new();
    readonly HashRange _hashRange = new();
    readonly HttpClient _httpClient;
    readonly AsyncRetryPolicy<HttpResponseMessage> _policy;

    int _hashesInProgress;

    public HashRangeProcessor(HttpClient httpClient, AsyncRetryPolicy<HttpResponseMessage> policy)
    {
        _httpClient = httpClient;
        _policy = policy;
    }

    public Statistics Statistics { get; } = new();

    public void Dispose() => _cancellationTokenSource.Dispose();

    async Task<HashRangeWebRequest> GetPwnedPasswordsRangeFromWebAsync(int i, CancellationToken cancellationToken)
    {
        var hashRequest = await HashRangeWebRequest.StartAsync(_httpClient, i, _policy, cancellationToken)
            .ConfigureAwait(false);

        var elapsed = hashRequest.ElapsedMilliseconds;
        Interlocked.Add(ref Statistics.CloudflareRequestTimeHeaders, elapsed);
        Interlocked.Increment(ref Statistics.CloudflareRequests);

        if (hashRequest.ResponseMessage.Headers.TryGetValues("CF-Cache-Status", out var values) && values != null)
        {
            switch (values.FirstOrDefault())
            {
                case "HIT":
                    Interlocked.Increment(ref Statistics.CloudflareHits);
                    break;
                default:
                    Interlocked.Increment(ref Statistics.CloudflareMisses);
                    break;
            }
        }

        return hashRequest;
    }

    public async Task ProcessRangesAsync(PwnedPasswordsDownloader.Settings settings)
    {
        var downloadTasks = Channel.CreateBounded<(int, Task<HashRangeWebRequest>)>(
            new BoundedChannelOptions(settings.Parallelism)
            {
                SingleReader = settings.SingleFile,
                SingleWriter = true,
                AllowSynchronousContinuations = true
            });

        var cancellationToken = _cancellationTokenSource.Token;

        var producerTask = Task.Run(
            () => StartDownloadsAsync(downloadTasks.Writer, cancellationToken),
            cancellationToken);

        try
        {
            if (settings.SingleFile)
            {
                await ProcessSingleFileAsync(settings, downloadTasks, cancellationToken);
            }
            else
            {
                await ProcessMultipleFilesAsync(settings, downloadTasks, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _cancellationTokenSource.Cancel();

            await producerTask.ConfigureAwait(false);
        }
    }

    async Task StartDownloadsAsync(ChannelWriter<(int, Task<HashRangeWebRequest>)> channelWriter,
        CancellationToken cancellationToken)
    {
        try
        {
            for (var i = 0; i < (100 * 1024) + (0 * 1024 * 1024); i++)
            {
                var currentHash = i;
                var task = Task.Run(() => GetPwnedPasswordsRangeFromWebAsync(currentHash, cancellationToken),
                    cancellationToken);

                await channelWriter.WriteAsync((i, task), cancellationToken).ConfigureAwait(false);
            }

            channelWriter.TryComplete();
        }
        catch (Exception e)
        {
            channelWriter.TryComplete(e);
        }
    }

    sealed class HashRangeWebRequest : IDisposable
    {
        static readonly double s_ticksPerMillisecond = 1000.0 / Stopwatch.Frequency;
        readonly long _timestamp;

        HashRangeWebRequest(int hashRangeIndex, HttpResponseMessage message, long timestamp)
        {
            HashRangeIndex = hashRangeIndex;
            ResponseMessage = message;
            _timestamp = timestamp;
        }

        public int HashRangeIndex { get; }
        public HttpResponseMessage ResponseMessage { get; }

        public long ElapsedMilliseconds
            => unchecked((long)(s_ticksPerMillisecond * Math.Max(0L, Stopwatch.GetTimestamp() - _timestamp)));

        public void Dispose() => ResponseMessage?.Dispose();

        public static async Task<HashRangeWebRequest> StartAsync(HttpClient httpClient, int hashRangeIndex,
            IAsyncPolicy<HttpResponseMessage> policy,
            CancellationToken cancellationToken)
        {
            var requestUri = HashRange.GetHashRange(hashRangeIndex);

            var timestamp = Stopwatch.GetTimestamp();

            var message = await policy.ExecuteAsync(async () =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, requestUri)
                {
                    Version = httpClient.DefaultRequestVersion,
                    VersionPolicy = httpClient.DefaultVersionPolicy
                };
                return await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                    .ConfigureAwait(false);
            }).ConfigureAwait(false);

            if (null == message)
            {
                throw new InvalidOperationException("Request started without message.");
            }

            return new(hashRangeIndex, message, timestamp);
        }
    }
}
