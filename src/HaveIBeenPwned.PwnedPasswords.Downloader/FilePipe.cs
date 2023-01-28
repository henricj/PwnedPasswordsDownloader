// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO.Pipelines;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace HaveIBeenPwned.PwnedPasswords;

class FilePipe : IDisposable
{
    readonly SafeFileHandle _handle;
    readonly Pipe _pipe;
    readonly Task _readerTask;
    bool _disposedValue;
    long _offset;

    internal FilePipe(SafeFileHandle handle)
    {
        _handle = handle;
        _pipe = new();
        _readerTask = StartWriter();
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    async Task StartWriter()
    {
        try
        {
            while (true)
            {
                if (!_pipe.Reader.TryRead(out var result))
                {
                    await _pipe.Reader.ReadAsync().ConfigureAwait(false);
                }

                foreach (var item in result.Buffer)
                {
                    await RandomAccess.WriteAsync(_handle, item, _offset).ConfigureAwait(false);
                    _offset += item.Length;
                }

                _pipe.Reader.AdvanceTo(result.Buffer.End);

                if (result.IsCompleted)
                {
                    break;
                }
            }
        }
        finally
        {
            await _pipe.Reader.CompleteAsync().ConfigureAwait(false);
        }
    }

    internal void Write(ReadOnlySpan<byte> span)
    {
        var destination = _pipe.Writer.GetSpan(span.Length);
        span.CopyTo(destination);
        _pipe.Writer.Advance(span.Length);
    }

    internal void Write(ReadOnlyMemory<char> memory) => Write(memory.Span);

    internal void Write(ReadOnlySpan<char> span) =>
        _pipe.Writer.Advance(Encoding.UTF8.GetBytes(span, _pipe.Writer.GetSpan(Encoding.UTF8.GetByteCount(span))));

    internal async ValueTask FlushAsync() => await _pipe.Writer.FlushAsync().ConfigureAwait(false);

    internal async Task CloseAsync()
    {
        _pipe.Writer.Complete();
        if (_pipe.Writer.UnflushedBytes > 0)
        {
            await _pipe.Writer.FlushAsync().ConfigureAwait(false);
        }

        await _readerTask.ConfigureAwait(false);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposedValue)
        {
            if (disposing)
            {
                _handle.Dispose();
            }

            _disposedValue = true;
        }
    }
}
