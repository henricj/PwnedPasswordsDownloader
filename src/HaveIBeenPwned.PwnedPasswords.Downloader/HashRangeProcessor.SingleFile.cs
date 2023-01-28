// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Channels;

namespace HaveIBeenPwned.PwnedPasswords.Downloader;

sealed partial class HashRangeProcessor
{
    static readonly StreamPipeReaderOptions s_singleFilePipeReaderOptions =
        new(bufferSize: 64 * 1024, leaveOpen: true);

    static readonly StreamPipeWriterOptions s_singleFilePipeWriterOptions =
        new(minimumBufferSize: 64 * 1024, leaveOpen: true);

    static readonly byte[] s_eol = Encoding.ASCII.GetBytes(Environment.NewLine);

    async Task ProcessSingleFileAsync(PwnedPasswordsDownloader.Settings settings,
        Channel<(int, Task<HashRangeWebRequest>)> downloadTasks, CancellationToken cancellationToken)
    {
        await using var file = File.Open($"{settings.OutputFile}.txt",
            new FileStreamOptions
            {
                Access = FileAccess.Write,
                BufferSize = 512 * 1024,
                Mode = FileMode.Create,
                Options = FileOptions.Asynchronous,
                Share = FileShare.None
            });

        var writer = PipeWriter.Create(file, s_singleFilePipeWriterOptions);

        await foreach (var (currentHash, item) in downloadTasks.Reader.ReadAllAsync(cancellationToken)
                           .ConfigureAwait(false))
        {
            var prefix = HashRange.GetHashRange(currentHash);

            using var rangeRequest = await item.ConfigureAwait(false);
            await using var inputStream =
                await rangeRequest.ResponseMessage.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);

            var reader = PipeReader.Create(inputStream, s_singleFilePipeReaderOptions);

            await WriteSingleFileAsync(reader, writer, prefix, cancellationToken).ConfigureAwait(false);

            Debug.Assert(currentHash == Statistics.HashesDownloaded);
            Statistics.HashesDownloaded++;

            var elapsed = rangeRequest.ElapsedMilliseconds;
            Interlocked.Add(ref Statistics.CloudflareRequestTimeTotal, elapsed);

            await reader.CompleteAsync();
        }

        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        await writer.CompleteAsync().ConfigureAwait(false);

        await file.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    static async ValueTask WriteSingleFileAsync(PipeReader reader, PipeWriter writer, string prefix,
        CancellationToken cancellationToken)
    {
        var prefixBytes = Encoding.ASCII.GetBytes(prefix);

        for (;;)
        {
            if (!reader.TryRead(out var result))
            {
                result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            }

            if (result.IsCompleted)
            {
                break;
            }

            var buffer = result.Buffer;

            var position = ParseBuffer(ref buffer, writer, prefixBytes);

            reader.AdvanceTo(position, buffer.End);

            if (writer.UnflushedBytes > 32 * 1024)
            {
                await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        static void WriteLine(ReadOnlySpan<byte> readOnlySpan, ReadOnlySpan<byte> prefix, PipeWriter pipeWriter)
        {
            if (readOnlySpan.Length <= 8) // A valid line can't be less than 8 bytes.
            {
                return;
            }

            var length = prefix.Length + readOnlySpan.Length + s_eol.Length;

            var output = pipeWriter.GetSpan(length);

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
}
