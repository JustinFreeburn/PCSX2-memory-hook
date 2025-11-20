using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.IO;
using System.Text;

class Program
{
    const int PROCESS_VM_READ = 0x0010;
    const int PROCESS_QUERY_INFORMATION = 0x0400;

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(
        int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    static void Main(string[] args)
    {
        string processName = "pcsx2";
        IntPtr address = (IntPtr)0x205DE240;
        int bufferSize = 128;

        Process p = GetProcessByName(processName);
        if (p == null)
        {
            Console.WriteLine("PCSX2 not found.");
            return;
        }

        IntPtr handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, p.Id);
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("OpenProcess failed.");
            return;
        }

        Console.WriteLine("Attached to PCSX2. Sniffing...");

        string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "dump_clean.txt");

        byte[] buffer = new byte[bufferSize];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string last = "";

        using (var fs = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
        using (var sw = new StreamWriter(fs, Encoding.UTF8) { AutoFlush = true })
        {
            while (true)
            {
                if (!ReadProcessMemory(handle, address, buffer, buffer.Length, out int bytesRead))
                    continue;

                string raw = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                int nullIndex = raw.IndexOf('\0');

                if (nullIndex >= 0)
                {
                    raw = raw.Substring(0, nullIndex);
                }

                string cleaned = raw.Trim();

                if (cleaned.Length < 5)
                {
                    continue;
                }

                // NOTE: Exclude...
                //if (!cleaned.StartsWith("./ee_files/"))
                //{
                //    continue;
                //}

                // NOTE: Skip if identical to last string
                if (cleaned == last)
                {
                    continue;
                }

                last = cleaned;

                // NOTE: Skip if we've seen it already
                if (seen.Add(cleaned))
                {
                    sw.WriteLine(cleaned);
                    Console.WriteLine(cleaned);
                }

                // NOTE: a tiny sleep for CPU relief
                // System.Threading.Thread.Sleep(0);
            }
        }

        CloseHandle(handle);
    }

    static Process GetProcessByName(string name)
    {
        Process[] procs = Process.GetProcessesByName(name);
        return procs.Length > 0 ? procs[0] : null;
    }
}
