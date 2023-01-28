// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Threading.Channels;

namespace HaveIBeenPwned.PwnedPasswords.Downloader;

sealed partial class HashRangeProcessor
{
    async Task ProcessMultipleFilesAsync(PwnedPasswordsDownloader.Settings settings,
        Channel<(int, Task<HashRangeWebRequest>)> downloadTasks, CancellationToken cancellationToken)
    {
        DirectoryInfo dir = new(settings.OutputFile);

        var workerTasks = new Task[settings.Parallelism];
        for (var i = 0; i < workerTasks.Length; i++)
        {
            workerTasks[i] = Task.Run(() => DownloadRangeToFileAsync(downloadTasks.Reader, dir),
                cancellationToken);
        }

        await Task.WhenAll(workerTasks).ConfigureAwait(false);
    }

    async Task DownloadRangeToFileAsync(ChannelReader<(int, Task<HashRangeWebRequest>)> channelReader,
        DirectoryInfo outputDirectory)
    {
        try
        {
            for (;;)
            {
                if (!channelReader.TryRead(out var next))
                {
                    if (!await channelReader.WaitToReadAsync(_cancellationTokenSource.Token).ConfigureAwait(false))
                    {
                        break;
                    }
                }

                var (currentHash, task) = next;

                if (null == task)
                {
                    continue;
                }

                await using (var file = File.Open(_hashRange.GetHashFilePath(outputDirectory, currentHash),
                                 new FileStreamOptions
                                 {
                                     Access = FileAccess.Write,
                                     Mode = FileMode.Create,
                                     Share = FileShare.None,
                                     Options = FileOptions.Asynchronous | FileOptions.SequentialScan
                                 }))
                {
                    using var hashRequest = await task.ConfigureAwait(false);

                    Interlocked.Increment(ref _hashesInProgress);

                    await hashRequest.ResponseMessage.Content.CopyToAsync(file, _cancellationTokenSource.Token)
                        .ConfigureAwait(false);

                    var elapsed = hashRequest.ElapsedMilliseconds;
                    Interlocked.Add(ref Statistics.CloudflareRequestTimeTotal, elapsed);
                }

                Interlocked.Increment(ref Statistics.HashesDownloaded);
            }
        }
        catch (Exception)
        {
            _cancellationTokenSource.Cancel();
            throw;
        }
    }
}
