using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Avalonia.Media;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace MCCBounceEnable.Linux.Views;

public partial class MainWindow : Window
{
    private const string ProcessName = "MCC-Win64-Shipping.exe";
    private const string ModuleName = "halo2.dll";

    private const int PtraceAttach = 16;
    private const int PtraceDetach = 17;
    private const int Wuntraced = 2;
    private const int SigCont = 18;

    private static readonly byte?[] TickRatePattern =
        ParsePattern("48 8B 05 ?? ?? ?? ?? F3 0F 10 40 04 C3 CC CC CC 48 8B 05");

    private static readonly byte[] TickRate30 = { 0x1E, 0x00, 0x89, 0x88, 0x08, 0x3D };
    private static readonly byte[] TickRate25 = { 0x19, 0x00, 0x89, 0x88, 0x08, 0x3D };
    private static readonly byte[] TickRate60 = { 0x3C, 0x00, 0x89, 0x88, 0x88, 0x3C };

    private IntPtr _tickRateAddress = IntPtr.Zero;
    private long? _patternAddress;
    private bool _suppressTickrateChange;
    private bool _operationInProgress;

    [DllImport("libc", SetLastError = true)]
    private static extern int ptrace(int request, int pid, IntPtr addr, IntPtr data);

    [DllImport("libc", SetLastError = true)]
    private static extern int waitpid(int pid, out int status, int options);

    public MainWindow()
    {
        InitializeComponent();
        SetTickrateControlsEnabled(false);
    }

    private async void TickrateCheckBox_OnChanged(object? sender, RoutedEventArgs e)
    {
        if (_suppressTickrateChange || _operationInProgress)
        {
            return;
        }

        if (TickrateCheckBox.IsChecked == true)
        {
            SetTickrateSelection(30);
            await ApplyTickrateAsync(30);
            return;
        }

        await ApplyTickrateAsync(60);
    }

    private async void Pal25CheckBox_OnChanged(object? sender, RoutedEventArgs e)
    {
        if (_suppressTickrateChange || _operationInProgress)
        {
            return;
        }

        if (Pal25CheckBox.IsChecked == true)
        {
            SetTickrateSelection(25);
            await ApplyTickrateAsync(25);
            return;
        }

        await ApplyTickrateAsync(60);
    }

    private async void RescanButton_OnClick(object? sender, RoutedEventArgs e)
    {
        if (_operationInProgress) return;
        _tickRateAddress = IntPtr.Zero;
        _patternAddress = null;
        await ProbeTickrateAsync();
    }

    private async void AttachButton_OnClick(object? sender, RoutedEventArgs e)
    {
        if (_operationInProgress) return;
        await ProbeTickrateAsync();
    }

    private async void VerifyButton_OnClick(object? sender, RoutedEventArgs e)
    {
        if (_operationInProgress) return;
        await ProbeTickrateAsync();
    }

    private async void ReadBytesButton_OnClick(object? sender, RoutedEventArgs e)
    {
        if (_operationInProgress) return;
        _operationInProgress = true;
        SetAllControlsEnabled(false);
        UpdateAttachStatus(false, "Reading tickrate bytes...");
        var result = await Task.Run(ReadCurrentBytes);
        ApplyReadBytesResult(result);
        _operationInProgress = false;
    }

    private async void ApplyBytesButton_OnClick(object? sender, RoutedEventArgs e)
    {
        if (_operationInProgress) return;
        string? input = TestBytesTextBox.Text;
        _operationInProgress = true;
        SetAllControlsEnabled(false);
        UpdateAttachStatus(false, "Applying test bytes...");
        var result = await Task.Run(() => ApplyTestBytes(input));
        ApplyTestBytesResult(result);
        _operationInProgress = false;
    }

    private async Task ProbeTickrateAsync()
    {
        _operationInProgress = true;
        SetAllControlsEnabled(false);
        UpdateAttachStatus(false, "Scanning for tickrate... THE GAME WILL FREEZE!");
        var result = await Task.Run(ProbeTickrate);
        ApplyResultToUi(result, isWrite: false);
        _operationInProgress = false;
    }

    private async Task ApplyTickrateAsync(int desired)
    {
        _operationInProgress = true;
        SetAllControlsEnabled(false);
        UpdateAttachStatus(false, $"Setting tickrate to {desired} Hz...");
        var result = await Task.Run(() => ApplyTickrate(desired));
        ApplyResultToUi(result, isWrite: true);
        _operationInProgress = false;
    }

    private void ApplyResultToUi(OperationResult result, bool isWrite)
    {
        if (!result.Success)
        {
            UpdateAttachStatus(false, result.Message);
            UpdateTickrateStatus("Tickrate: unknown.");
            UpdateAddressStatus(result.PatternAddress, result.TickAddress);
            SetTickrateControlsEnabled(false);
            AttachButton.IsEnabled = true;
            if (!string.IsNullOrWhiteSpace(result.ErrorPopup))
            {
                ShowErrorWindow(result.ErrorPopup);
            }
            return;
        }

        UpdateAttachStatus(true, result.Message);
        UpdateAddressStatus(result.PatternAddress, result.TickAddress);
        SetAllControlsEnabled(true);

        if (result.CurrentTickrate is 30 or 60)
        {
            UpdateTickrateStatus($"Tickrate: {result.CurrentTickrate} Hz.");
            SetTickrateSelection(result.CurrentTickrate.Value);
        }
        else if (result.CurrentTickrate == 25)
        {
            UpdateTickrateStatus("Tickrate: 25 Hz.");
            SetTickrateSelection(25);
        }
        else
        {
            UpdateTickrateStatus("Tickrate: unknown.");
        }

        if (isWrite && result.CurrentTickrate is null)
        {
            UpdateTickrateStatus("Tickrate: write complete (verification failed)." );
        }
    }

    private void ApplyReadBytesResult(OperationResult result)
    {
        if (!result.Success)
        {
            UpdateAttachStatus(false, result.Message);
            SetAllControlsEnabled(true);
            if (!string.IsNullOrWhiteSpace(result.ErrorPopup))
            {
                ShowErrorWindow(result.ErrorPopup);
            }
            return;
        }

        UpdateAttachStatus(true, result.Message);
        UpdateAddressStatus(result.PatternAddress, result.TickAddress);
        SetAllControlsEnabled(true);

        if (result.CurrentBytes is { Length: 6 })
        {
            TestBytesTextBox.Text = BytesToHex(result.CurrentBytes);
            UpdateTestBytesStatus("Test bytes: read current value.");
        }
    }

    private void ApplyTestBytesResult(OperationResult result)
    {
        if (!result.Success)
        {
            UpdateAttachStatus(false, result.Message);
            UpdateTestBytesStatus("Test bytes: apply failed.");
            SetAllControlsEnabled(true);
            if (!string.IsNullOrWhiteSpace(result.ErrorPopup))
            {
                ShowErrorWindow(result.ErrorPopup);
            }
            return;
        }

        UpdateAttachStatus(true, result.Message);
        UpdateAddressStatus(result.PatternAddress, result.TickAddress);
        SetAllControlsEnabled(true);
        UpdateTestBytesStatus("Test bytes: applied.");
    }

    private void ShowErrorWindow(string errorMessage)
    {
        Dispatcher.UIThread.Post(async () =>
        {
            ErrorWindow errorWindow = new();
            errorWindow.ErrorTextBlock.Text = errorMessage;

            if (VisualRoot is Window window)
            {
                await errorWindow.ShowDialog(window);
            }
            else
            {
                Console.Write("The error window broke somehow. Please submit an Issue for this in GitHub.");
            }
        });
    }

    private OperationResult ProbeTickrate()
    {
        int pid = GetProcessIdByName(ProcessName);
        if (pid == -1)
        {
            return OperationResult.Fail("MCC not running.",
                "Could not locate MCC. Please start the game and load into Halo 2.");
        }

        if (!TryAttach(pid, out string attachError))
        {
            return OperationResult.Fail("Failed to attach to MCC.", attachError);
        }

        try
        {
            using var mem = OpenProcessMemory(pid);
            if (mem == null)
            {
                return OperationResult.Fail("Failed to open /proc mem.",
                    "Could not open /proc/[pid]/mem. Run this program as root/sudo.");
            }

            long? tickAddress = EnsureTickrateAddress(pid, mem);
            if (tickAddress == null)
            {
                return OperationResult.Fail("Tickrate pattern not found.",
                    "Could not locate the Halo 2 tickrate pattern. Make sure you are in Halo 2 (classic) and in-game.")
                    .WithAddresses(_patternAddress, null);
            }

            int? current = ReadTickrate(mem, tickAddress.Value);
            return OperationResult.Ok("Tickrate located.", current)
                .WithAddresses(_patternAddress, tickAddress);
        }
        catch (Exception ex)
        {
            return OperationResult.Fail("Tickrate probe failed.", ex.Message)
                .WithAddresses(_patternAddress, _tickRateAddress == IntPtr.Zero ? null : _tickRateAddress.ToInt64());
        }
        finally
        {
            DetachProcess(pid);
        }
    }

    private OperationResult ApplyTickrate(int desired)
    {
        int pid = GetProcessIdByName(ProcessName);
        if (pid == -1)
        {
            return OperationResult.Fail("MCC not running.",
                "Could not locate MCC. Please start the game and load into Halo 2.");
        }

        if (!TryAttach(pid, out string attachError))
        {
            return OperationResult.Fail("Failed to attach to MCC.", attachError);
        }

        try
        {
            using var mem = OpenProcessMemory(pid);
            if (mem == null)
            {
                return OperationResult.Fail("Failed to open /proc mem.",
                    "Could not open /proc/[pid]/mem. Run this program as root/sudo.");
            }

            long? tickAddress = EnsureTickrateAddress(pid, mem);
            if (tickAddress == null)
            {
                return OperationResult.Fail("Tickrate pattern not found.",
                    "Could not locate the Halo 2 tickrate pattern. Make sure you are in Halo 2 (classic) and in-game.")
                    .WithAddresses(_patternAddress, null);
            }

            byte[] data = desired switch
            {
                25 => TickRate25,
                30 => TickRate30,
                _ => TickRate60
            };
            WriteBytes(mem, tickAddress.Value, data);

            int? current = ReadTickrate(mem, tickAddress.Value);
            return OperationResult.Ok($"Tickrate set to {desired} Hz.", current)
                .WithAddresses(_patternAddress, tickAddress);
        }
        catch (Exception ex)
        {
            return OperationResult.Fail("Tickrate write failed.", ex.Message)
                .WithAddresses(_patternAddress, _tickRateAddress == IntPtr.Zero ? null : _tickRateAddress.ToInt64());
        }
        finally
        {
            DetachProcess(pid);
        }
    }

    private OperationResult ReadCurrentBytes()
    {
        int pid = GetProcessIdByName(ProcessName);
        if (pid == -1)
        {
            return OperationResult.Fail("MCC not running.",
                "Could not locate MCC. Please start the game and load into Halo 2.");
        }

        if (!TryAttach(pid, out string attachError))
        {
            return OperationResult.Fail("Failed to attach to MCC.", attachError);
        }

        try
        {
            using var mem = OpenProcessMemory(pid);
            if (mem == null)
            {
                return OperationResult.Fail("Failed to open /proc mem.",
                    "Could not open /proc/[pid]/mem. Run this program as root/sudo.");
            }

            long? tickAddress = EnsureTickrateAddress(pid, mem);
            if (tickAddress == null)
            {
                return OperationResult.Fail("Tickrate pattern not found.",
                    "Could not locate the Halo 2 tickrate pattern. Make sure you are in Halo 2 (classic) and in-game.")
                    .WithAddresses(_patternAddress, null);
            }

            byte[] bytes = ReadBytes(mem, tickAddress.Value, TickRate30.Length);
            int? current = ReadTickrate(mem, tickAddress.Value);
            return OperationResult.Ok("Tickrate bytes read.", current)
                .WithAddresses(_patternAddress, tickAddress)
                .WithCurrentBytes(bytes);
        }
        catch (Exception ex)
        {
            return OperationResult.Fail("Read bytes failed.", ex.Message)
                .WithAddresses(_patternAddress, _tickRateAddress == IntPtr.Zero ? null : _tickRateAddress.ToInt64());
        }
        finally
        {
            DetachProcess(pid);
        }
    }

    private OperationResult ApplyTestBytes(string? input)
    {
        if (!TryParseHexBytes(input, TickRate30.Length, out byte[]? bytes, out string? parseError))
        {
            return OperationResult.Fail("Invalid hex bytes.", parseError);
        }

        int pid = GetProcessIdByName(ProcessName);
        if (pid == -1)
        {
            return OperationResult.Fail("MCC not running.",
                "Could not locate MCC. Please start the game and load into Halo 2.");
        }

        if (!TryAttach(pid, out string attachError))
        {
            return OperationResult.Fail("Failed to attach to MCC.", attachError);
        }

        try
        {
            using var mem = OpenProcessMemory(pid);
            if (mem == null)
            {
                return OperationResult.Fail("Failed to open /proc mem.",
                    "Could not open /proc/[pid]/mem. Run this program as root/sudo.");
            }

            long? tickAddress = EnsureTickrateAddress(pid, mem);
            if (tickAddress == null)
            {
                return OperationResult.Fail("Tickrate pattern not found.",
                    "Could not locate the Halo 2 tickrate pattern. Make sure you are in Halo 2 (classic) and in-game.")
                    .WithAddresses(_patternAddress, null);
            }

            WriteBytes(mem, tickAddress.Value, bytes!);
            int? current = ReadTickrate(mem, tickAddress.Value);
            return OperationResult.Ok("Test bytes written.", current)
                .WithAddresses(_patternAddress, tickAddress);
        }
        catch (Exception ex)
        {
            return OperationResult.Fail("Test bytes write failed.", ex.Message)
                .WithAddresses(_patternAddress, _tickRateAddress == IntPtr.Zero ? null : _tickRateAddress.ToInt64());
        }
        finally
        {
            DetachProcess(pid);
        }
    }

    private static FileStream? OpenProcessMemory(int pid)
    {
        try
        {
            return new FileStream($"/proc/{pid}/mem", FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
        }
        catch
        {
            return null;
        }
    }

    private long? EnsureTickrateAddress(int pid, FileStream mem)
    {
        if (_tickRateAddress != IntPtr.Zero)
        {
            if (IsTickrateAddressValid(mem, _tickRateAddress.ToInt64()))
            {
                return _tickRateAddress.ToInt64();
            }

            _tickRateAddress = IntPtr.Zero;
        }

        long? patternAddress = FindPatternAddress(pid, mem, ModuleName, TickRatePattern);
        if (patternAddress == null)
        {
            patternAddress = FindPatternAddress(pid, mem, null, TickRatePattern);
            if (patternAddress == null)
            {
                return null;
            }
        }

        _patternAddress = patternAddress;

        int rel32 = ReadInt32(mem, patternAddress.Value + 3);
        long addressLocation = patternAddress.Value + 7 + rel32;
        long pointer = ReadInt64(mem, addressLocation);
        long tickAddress = pointer + 2;

        _tickRateAddress = new IntPtr(tickAddress);
        return tickAddress;
    }

    private static bool IsTickrateAddressValid(FileStream mem, long address)
    {
        try
        {
            byte[] bytes = ReadBytes(mem, address, TickRate30.Length);
            return Matches(bytes, TickRate25) || Matches(bytes, TickRate30) || Matches(bytes, TickRate60);
        }
        catch
        {
            return false;
        }
    }

    private static int? ReadTickrate(FileStream mem, long address)
    {
        try
        {
            byte[] bytes = ReadBytes(mem, address, TickRate30.Length);
            if (Matches(bytes, TickRate25))
            {
                return 25;
            }

            if (Matches(bytes, TickRate30))
            {
                return 30;
            }

            if (Matches(bytes, TickRate60))
            {
                return 60;
            }
        }
        catch
        {
            return null;
        }

        return null;
    }

    private static bool Matches(byte[] value, byte[] expected)
    {
        if (value.Length != expected.Length)
        {
            return false;
        }

        for (int i = 0; i < expected.Length; i++)
        {
            if (value[i] != expected[i])
            {
                return false;
            }
        }

        return true;
    }

    private static long? FindPatternAddress(int pid, FileStream mem, string? moduleName, byte?[] pattern)
    {
        var regions = moduleName == null
            ? GetReadableRegions(pid)
            : GetModuleRegions(pid, moduleName);
        if (regions.Count == 0)
        {
            return null;
        }

        const int chunkSize = 1024 * 1024;
        int patternLength = pattern.Length;
        byte[] buffer = new byte[chunkSize + patternLength];

        foreach (var region in regions)
        {
            long regionSize = region.End - region.Start;
            if (regionSize <= 0)
            {
                continue;
            }

            long offset = 0;
            int overlap = 0;

            while (offset < regionSize)
            {
                int toRead = (int)Math.Min(chunkSize, regionSize - offset);
                int read;
                try
                {
                    mem.Position = region.Start + offset;
                    read = mem.Read(buffer, overlap, toRead);
                }
                catch (IOException)
                {
                    break;
                }
                if (read <= 0)
                {
                    break;
                }

                int total = overlap + read;
                int index = FindPattern(buffer, total, pattern);
                if (index >= 0)
                {
                    return region.Start + offset - overlap + index;
                }

                overlap = Math.Min(patternLength - 1, total);
                if (overlap > 0)
                {
                    Array.Copy(buffer, total - overlap, buffer, 0, overlap);
                }

                offset += read;
            }
        }

        return null;
    }

    private static int FindPattern(byte[] buffer, int length, byte?[] pattern)
    {
        int patternLength = pattern.Length;
        int limit = length - patternLength;
        for (int i = 0; i <= limit; i++)
        {
            bool matched = true;
            for (int j = 0; j < patternLength; j++)
            {
                byte? expected = pattern[j];
                if (expected.HasValue && buffer[i + j] != expected.Value)
                {
                    matched = false;
                    break;
                }
            }

            if (matched)
            {
                return i;
            }
        }

        return -1;
    }

    private static List<MemRegion> GetModuleRegions(int pid, string moduleName)
    {
        var regions = new List<MemRegion>();
        string mapsPath = $"/proc/{pid}/maps";
        if (!File.Exists(mapsPath))
        {
            return regions;
        }

        foreach (string line in File.ReadLines(mapsPath))
        {
            if (!line.Contains(moduleName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                continue;
            }

            string range = parts[0];
            string perms = parts[1];
            if (!perms.StartsWith('r'))
            {
                continue;
            }

            int dash = range.IndexOf('-');
            if (dash <= 0)
            {
                continue;
            }

            if (!long.TryParse(range[..dash], System.Globalization.NumberStyles.HexNumber, null, out long start))
            {
                continue;
            }

            if (!long.TryParse(range[(dash + 1)..], System.Globalization.NumberStyles.HexNumber, null, out long end))
            {
                continue;
            }

            regions.Add(new MemRegion(start, end, perms));
        }

        return regions;
    }

    private static List<MemRegion> GetReadableRegions(int pid)
    {
        var regions = new List<MemRegion>();
        string mapsPath = $"/proc/{pid}/maps";
        if (!File.Exists(mapsPath))
        {
            return regions;
        }

        foreach (string line in File.ReadLines(mapsPath))
        {
            string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                continue;
            }

            string range = parts[0];
            string perms = parts[1];
            if (!perms.StartsWith('r'))
            {
                continue;
            }

            int dash = range.IndexOf('-');
            if (dash <= 0)
            {
                continue;
            }

            if (!long.TryParse(range[..dash], System.Globalization.NumberStyles.HexNumber, null, out long start))
            {
                continue;
            }

            if (!long.TryParse(range[(dash + 1)..], System.Globalization.NumberStyles.HexNumber, null, out long end))
            {
                continue;
            }

            regions.Add(new MemRegion(start, end, perms));
        }

        return regions;
    }

    private static byte[] ReadBytes(FileStream mem, long address, int length)
    {
        byte[] buffer = new byte[length];
        mem.Position = address;
        int read = mem.Read(buffer, 0, length);
        if (read != length)
        {
            throw new IOException("Failed to read memory.");
        }

        return buffer;
    }

    private static void WriteBytes(FileStream mem, long address, byte[] data)
    {
        mem.Position = address;
        mem.Write(data, 0, data.Length);
        mem.Flush();
    }

    private static int ReadInt32(FileStream mem, long address)
    {
        byte[] bytes = ReadBytes(mem, address, 4);
        return BitConverter.ToInt32(bytes, 0);
    }

    private static long ReadInt64(FileStream mem, long address)
    {
        byte[] bytes = ReadBytes(mem, address, 8);
        return BitConverter.ToInt64(bytes, 0);
    }

    private static bool TryAttach(int pid, out string error)
    {
        const int maxAttempts = 200;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            if (ptrace(PtraceAttach, pid, IntPtr.Zero, IntPtr.Zero) != -1)
            {
                _ = waitpid(pid, out _, Wuntraced);
                error = string.Empty;
                return true;
            }

            Thread.Sleep(5);
        }

        error = "Failed to attach to the MCC process. Make sure no other tools are attached, and run as root/sudo.";
        return false;
    }

    private static void DetachProcess(int pid)
    {
        _ = ptrace(PtraceDetach, pid, IntPtr.Zero, new IntPtr(SigCont));
    }

    private static int GetProcessIdByName(string processName)
    {
        int lastPid = -1;
        string[] procEntries = Directory.GetDirectories("/proc");

        foreach (string entry in procEntries)
        {
            if (!int.TryParse(Path.GetFileName(entry), out int pid))
            {
                continue;
            }

            try
            {
                string cmdline = File.ReadAllText($"/proc/{pid}/cmdline");
                if (cmdline.Contains(processName, StringComparison.OrdinalIgnoreCase))
                {
                    lastPid = pid;
                }
            }
            catch
            {
                // Ignore processes we can't read.
            }
        }

        return lastPid;
    }

    private static byte?[] ParsePattern(string pattern)
    {
        string[] parts = pattern.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var result = new byte?[parts.Length];
        for (int i = 0; i < parts.Length; i++)
        {
            if (parts[i] == "??")
            {
                result[i] = null;
                continue;
            }

            result[i] = Convert.ToByte(parts[i], 16);
        }

        return result;
    }

    private static bool TryParseHexBytes(string? text, int expectedLength, out byte[]? bytes, out string? error)
    {
        bytes = null;
        error = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            error = "Enter hex bytes first.";
            return false;
        }

        string cleaned = text.Replace(" ", string.Empty)
            .Replace("\t", string.Empty)
            .Replace("\n", string.Empty)
            .Replace("\r", string.Empty);

        if (cleaned.Length != expectedLength * 2)
        {
            error = $"Expected {expectedLength} bytes ({expectedLength * 2} hex characters).";
            return false;
        }

        var result = new byte[expectedLength];
        for (int i = 0; i < expectedLength; i++)
        {
            string token = cleaned.Substring(i * 2, 2);
            if (!byte.TryParse(token, System.Globalization.NumberStyles.HexNumber, null, out byte value))
            {
                error = $"Invalid hex value: {token}.";
                return false;
            }

            result[i] = value;
        }

        bytes = result;
        return true;
    }

    private static string BytesToHex(byte[] bytes)
    {
        return BitConverter.ToString(bytes).Replace("-", " ");
    }

    private void UpdateAttachStatus(bool attached, string message)
    {
        AttachStatusIndicator.Background = attached
            ? new SolidColorBrush(Color.Parse("#FF2E7D32"))
            : new SolidColorBrush(Color.Parse("#FFC62828"));
        AttachStatusText.Text = message;
    }

    private void UpdateTickrateStatus(string message)
    {
        TickrateStatusText.Text = message;
    }

    private void UpdateTestBytesStatus(string message)
    {
        TestBytesStatusText.Text = message;
    }

    private void UpdateAddressStatus(long? patternAddress, long? tickAddress)
    {
        string patternText = patternAddress.HasValue ? $"0x{patternAddress.Value:X}" : "not found";
        string tickText = tickAddress.HasValue ? $"0x{tickAddress.Value:X}" : "unknown";
        AddressStatusText.Text = $"Pattern address: {patternText} | Tickrate address: {tickText}.";
    }

    private void SetTickrateSelection(int tickrate)
    {
        _suppressTickrateChange = true;
        TickrateCheckBox.IsChecked = tickrate == 30;
        Pal25CheckBox.IsChecked = tickrate == 25;
        _suppressTickrateChange = false;
    }

    private void SetTickrateControlsEnabled(bool enabled)
    {
        TickrateCheckBox.IsEnabled = enabled;
        Pal25CheckBox.IsEnabled = enabled;
        VerifyButton.IsEnabled = enabled;
        RescanButton.IsEnabled = enabled;
        ReadBytesButton.IsEnabled = enabled;
        ApplyBytesButton.IsEnabled = enabled;
        TestBytesTextBox.IsEnabled = enabled;
    }

    private void SetAllControlsEnabled(bool enabled)
    {
        AttachButton.IsEnabled = enabled;
        TickrateCheckBox.IsEnabled = enabled;
        Pal25CheckBox.IsEnabled = enabled;
        VerifyButton.IsEnabled = enabled;
        RescanButton.IsEnabled = enabled;
        ReadBytesButton.IsEnabled = enabled;
        ApplyBytesButton.IsEnabled = enabled;
        TestBytesTextBox.IsEnabled = enabled;
    }

    private readonly record struct MemRegion(long Start, long End, string Perms);

    private readonly record struct OperationResult(
        bool Success,
        string Message,
        string? ErrorPopup,
        long? PatternAddress,
        long? TickAddress,
        int? CurrentTickrate,
        byte[]? CurrentBytes)
    {
        public static OperationResult Ok(string message, int? currentTickrate) =>
            new(true, message, null, null, null, currentTickrate, null);

        public static OperationResult Fail(string message, string? errorPopup) =>
            new(false, message, errorPopup, null, null, null, null);

        public OperationResult WithAddresses(long? patternAddress, long? tickAddress) =>
            this with { PatternAddress = patternAddress, TickAddress = tickAddress };

        public OperationResult WithCurrentBytes(byte[] bytes) =>
            this with { CurrentBytes = bytes };
    }
}
