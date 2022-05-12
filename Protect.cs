#pragma warning disable CS0618
#pragma warning disable CA1416
using System.Diagnostics;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;

namespace Protect
{
    internal class Protect
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
        [DllImport("kernel32.dll")]
        internal static extern IntPtr VirtualProtect(IntPtr lpAddress, IntPtr dwSize, IntPtr flNewProtect, ref IntPtr lpflOldProtect);
        [DllImport("kernel32.dll")]
        internal static extern IntPtr ZeroMemory(IntPtr addr, IntPtr size);

        public struct PE
        {
            static public int[] SectionTabledWords = new int[] { 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x24 };
            static public int[] Bytes = new int[] { 0x1A, 0x1B };
            static public int[] Words = new int[] { 0x4, 0x16, 0x18, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x5C, 0x5E };
            static public int[] dWords = new int[] { 0x0, 0x8, 0xC, 0x10, 0x16, 0x1C, 0x20, 0x28, 0x2C, 0x34, 0x3C, 0x4C, 0x50, 0x54, 0x58, 0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x104, 0x108, 0x10C, 0x110, 0x114, 0x11C };
        }
        internal static void EraseSection(IntPtr address, int size)
        {
            IntPtr sz = (IntPtr)size;
            IntPtr dwOld = default(IntPtr);
            VirtualProtect(address, sz, (IntPtr)0x40, ref dwOld);
            ZeroMemory(address, sz);
            IntPtr temp = default(IntPtr);
            VirtualProtect(address, sz, dwOld, ref temp);
        }
        static public void WebSniffers()
        {

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;


            HttpWebRequest.DefaultWebProxy = new WebProxy();
            WebRequest.DefaultWebProxy = new WebProxy();

            if (GetModuleHandle("HTTPDebuggerBrowser.dll") != IntPtr.Zero || GetModuleHandle("FiddlerCore4.dll") != IntPtr.Zero || GetModuleHandle("RestSharp.dll") != IntPtr.Zero || GetModuleHandle("Titanium.Web.Proxy.dll") != IntPtr.Zero)
            {
                Environment.Exit(0);
            }
        }
        static public void AntiDebug()
        {

            bool isDebuggerPresent = true;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
            if (isDebuggerPresent)
            {
                Environment.Exit(0);
            }
        }
        static public void Sandboxie()
        {
            if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
            {
                Environment.Exit(0);
            }
        }
        static public void Emulation()
        {
            long tickCount = Environment.TickCount;
            Thread.Sleep(500);
            long tickCount2 = Environment.TickCount;
            if (((tickCount2 - tickCount) < 500L))
            {
                Environment.Exit(0);
            }
        }
        static public void DetectVM()
        {

            using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            using (ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get())
                foreach (ManagementBaseObject managementBaseObject in managementObjectCollection)
                    if ((managementBaseObject["Manufacturer"].ToString().ToLower() == "microsoft corporation" && managementBaseObject["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL")) || managementBaseObject["Manufacturer"].ToString().ToLower().Contains("vmware") || managementBaseObject["Model"].ToString() == "VirtualBox")
                    {
                        Environment.Exit(0);
                    }

            foreach (ManagementBaseObject managementBaseObject2 in new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_VideoController").Get())
                if (managementBaseObject2.GetPropertyValue("Name").ToString().Contains("VMware") && managementBaseObject2.GetPropertyValue("Name").ToString().Contains("VBox"))
                {
                    Environment.Exit(0);
                }
        }
        static public void AntiDump()
        {
            var process = Process.GetCurrentProcess();
            var base_address = process.MainModule.BaseAddress;
            var dwpeheader = Marshal.ReadInt32((IntPtr)(base_address + 0x3C));
            var wnumberofsections = Marshal.ReadInt16((IntPtr)(base_address + dwpeheader + 0x6));

            EraseSection(base_address, 30);

            for (int i = 0; i < PE.dWords.Length; i++)
                EraseSection((IntPtr)(base_address + dwpeheader + PE.dWords[i]), 4);

            for (int i = 0; i < PE.Words.Length; i++)
                EraseSection((IntPtr)(base_address + dwpeheader + PE.Words[i]), 2);

            for (int i = 0; i < PE.Bytes.Length; i++)
                EraseSection((IntPtr)(base_address + dwpeheader + PE.Bytes[i]), 1);

            int x = 0;
            int y = 0;

            while (x <= wnumberofsections)
            {
                if (y == 0)
                    EraseSection((IntPtr)((base_address + dwpeheader + 0xFA + (0x28 * x)) + 0x20), 2);

                EraseSection((IntPtr)((base_address + dwpeheader + 0xFA + (0x28 * x)) + PE.SectionTabledWords[y]), 4);

                y++;

                if (y == PE.SectionTabledWords.Length)
                {
                    x++;
                    y = 0;
                }
            }
        }
    }
}