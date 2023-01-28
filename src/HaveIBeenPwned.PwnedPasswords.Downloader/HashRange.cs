// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers.Binary;
using System.Collections.Concurrent;

namespace HaveIBeenPwned.PwnedPasswords.Downloader;

sealed class HashRange
{
    readonly ConcurrentDictionary<int, string> _dirPaths = new();

    public static string GetHashRange(int i)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, i);
        return Convert.ToHexString(bytes)[3..];
    }

    public string GetHashFilePath(DirectoryInfo baseDir, int currentHash)
    {
        var name = GetHashRange(currentHash);

        if (!_dirPaths.TryGetValue(currentHash, out var path))
        {
            var subDirPath = $"{name[^1]}{name[^2]}{name[^3]}{name[^4]}";

            var subDir = baseDir.CreateSubdirectory(subDirPath);

            path = subDir.FullName;

            _dirPaths.TryAdd(currentHash, path);
        }

        return Path.Combine(path, Path.ChangeExtension(name, ".txt"));
    }
}
