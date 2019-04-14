﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.ServiceProcess;
using System.Xml;
using IPInfo = System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<SCAdaptiveFirewall.InterestingSecurityFailure>>;
using System.Threading;
using System.Configuration;
using System.Globalization;
using System.Collections.ObjectModel;
using System.Net;
using static System.FormattableString;

namespace SCAdaptiveFirewall
{
    public partial class AdaptiveFirewall : ServiceBase
    {
        static readonly Object _loglock = new object ();
        static readonly StreamWriter _log = InitLog();
        static readonly string _blockscript = LoadBlockScript();

        readonly EventLogWatcher _seclogwatcher;
        readonly EventLogWatcher _rdplogwatcher;
        readonly Object _datalock = new object();
        readonly IPInfo _ipdeets = new IPInfo();

        /// <summary>
        ///  Constructor
        /// </summary>
        public AdaptiveFirewall()
        {
            InitializeComponent();
            ServiceName = "Adaptive firewall";
            CanStop = true;
            CanPauseAndContinue = false;
            AutoLog = true;

            // Subscribe to security event log
            // Logon failure events
            var subquery = new EventLogQuery("Security",
                PathType.LogName, "*[System/EventID=4625]");

            _seclogwatcher = new EventLogWatcher(subquery);
            _seclogwatcher.EventRecordWritten +=
                new EventHandler<EventRecordWrittenEventArgs>(
                    OnEventRecordWritten);

            // Subscribe to RDP event log event 140s
            subquery = new EventLogQuery(
                "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", 
                PathType.LogName, "*[System/EventID=140]");
            _rdplogwatcher = new EventLogWatcher(subquery);
            _rdplogwatcher.EventRecordWritten +=
                new EventHandler<EventRecordWrittenEventArgs>(
                    OnEventRecordWritten);
        }

        /// <summary>
        /// Get's the Powershell Script used to edit Windows Firewall
        /// from .exe embedded resources. Block.ps1 is copied there during
        /// compilation.
        /// </summary>
        /// <returns></returns>
        private static string LoadBlockScript()
        {
            MemoryStream ms = null;
            try
            {
                ms = new MemoryStream(Properties.Resources.BlockIp);
                using (var sr = new StreamReader(ms))
                {
                    ms = null;
                    return sr.ReadToEnd();
                }
            }
            finally
            {
                ms?.Dispose();
            }
        }
        /// <summary>
        ///  Setup log file in user's temp
        ///  folder. For localservice it's c:\windows\temp
        /// </summary>
        static StreamWriter InitLog()
        {
            var logpath = Path.Combine(Path.GetTempPath(), "AdaptiveFirewall.log");
            StreamWriter log = null;
            try
            {
                log = new StreamWriter(logpath, true);
                log.AutoFlush = true;
            }
            catch
            {
                log?.Dispose();
                throw;
            }
             
            return log;

        }

        public int SecFailureCountThreshold { get; } = 5;
        public static Collection<Subnet> LocalSubnets { get; private set; } = LoadLocalSubnets();

        /// <summary>
        /// Override method called by Windows when starting
        /// the service.
        /// </summary>
        /// <param name="args"></param>
        protected override void OnStart(string[] args)
        {
            _seclogwatcher.Enabled = true;
            _rdplogwatcher.Enabled = true;
        }

        /// <summary>
        /// Override method called by Windows when stopping
        /// the service.
        /// </summary>
        protected override void OnStop()
        {
            _seclogwatcher.Enabled = false;
            _rdplogwatcher.Enabled = false;
        }
        /// <summary>
        /// Writes line of output to diag log in
        /// temp folder
        /// </summary>
        /// <param name="infomessage"></param>
        static void WriteInfo(string infomessage)
        {
            lock (_loglock)
            {
                _log.WriteLine(Invariant($"[{DateTime.Now.ToString("o", CultureInfo.InvariantCulture).Replace('T',' ')} TID:{Thread.CurrentThread.ManagedThreadId:000}] {infomessage}"));
            }
        }

        /// <summary>
        /// Callback method that gets executed when an event is
        /// reported to the subscription. Can be called on
        /// multiple threads.
        /// </summary>
        public void OnEventRecordWritten(object sender,
            EventRecordWrittenEventArgs arg)
        {
            // Make sure there was no error reading the event.
            if (arg != null && arg.EventRecord != null)
            {
                var stopwatch = new Stopwatch();
                stopwatch.Start();
                ProcessEvent(arg.EventRecord);
                stopwatch.Stop();
                if (stopwatch.Elapsed.TotalMilliseconds > 500)
                {
                    WriteInfo(Invariant($"Took [{stopwatch.Elapsed.TotalSeconds}] seconds to process event"));
                }
                else
                {
                    WriteInfo(Invariant($"Took [{stopwatch.Elapsed.TotalMilliseconds}] milliseconds to process event"));
                }
            }
        }

        /// <summary>
        /// Kicks off handling of interesting events by reading 
        /// metadata from Event XML.
        /// </summary>
        /// <param name="er"></param>
       void ProcessEvent(EventRecord er)
        {
            WriteInfo(Invariant($"Received event {er.Id} from the subscription."));

            var isf = ParseEvent(er);

            if (isf.IP == null || !IPAddress.TryParse(isf.IP, out IPAddress ad))
            {
                WriteInfo("Couldn't read IP address from event.  Nothing to do.");
                return;
            }

            // Canonicalize IP
            isf.IP = ad.ToString();

            if (IsLocalAddress(ad))
            {
                WriteInfo($"No action required for {isf.IP}, it is a local address.");
                return;
            }

            BlockIpIfNecessary(isf);
        }

        public static InterestingSecurityFailure ParseEvent(EventRecord eventRecord)
        {
            if (eventRecord == null)
            {
                throw new ArgumentNullException(nameof(eventRecord));
            }

            var xml = new XmlDocument();
            xml.LoadXml(eventRecord.ToXml());
            var ns = new XmlNamespaceManager(xml.NameTable);
            ns.AddNamespace("a", "http://schemas.microsoft.com/win/2004/08/events/event");
       
            var isf = new InterestingSecurityFailure
            {
                Date = eventRecord.TimeCreated,
                EventId = eventRecord.Id
            };

            switch (eventRecord.Id)
            {
                case 4625:
                    isf.IP = (xml.SelectSingleNode("//a:Data[@Name=\"IpAddress\"]", ns))?.InnerText;
                    isf.UserName = (xml.SelectSingleNode("//a:Data[@Name=\"TargetUserName\"]", ns))?.InnerText;
                    isf.Domain = (xml.SelectSingleNode("//a:Data[@Name=\"TargetDomainName\"]", ns))?.InnerText;
                    break;
                case 140:
                    isf.IP = (xml.SelectSingleNode("//a:Data[@Name=\"IPString\"]", ns))?.InnerText;
                    break;
            }
            return isf;
        }

        /// <summary>
        /// Given an Ip determine if it is a "local"
        /// ip that should be ignored.  
        /// </summary>
        /// <param name="IPAddress"></param>
        /// <returns></returns>
        public static bool IsLocalAddress(IPAddress internetAddress)
        {
            if (internetAddress == null)
            {
                throw new ArgumentNullException(nameof(internetAddress));
            }

            if (internetAddress.IsIPv6LinkLocal) return true;

            foreach (var s in LocalSubnets)
            {
                if (Network.IsAddressInSubnet(internetAddress.ToString(), s))
                {
                    return true;
                }
            }

            return false;
        }


        /// <summary>
        /// Check if blocking is necessary depending on event type and
        /// how many failed attempts there have been 
        /// </summary>
        /// <param name="isf"></param>
        void BlockIpIfNecessary(InterestingSecurityFailure isf)
        {
            WriteInfo(Invariant($"[Event {isf.EventId}] IP: [{isf.IP}]"));
            // just straight up block event 140 ips for now!! as a test:)
            if (isf.EventId == 140)
            {
                TryBlockIp(isf.IP);
                return;
            }

            // if event 4625 check number of previous
            // failed attempts in past hour.

            int secfailures;
            lock (_datalock)
            {
                PruneIpInfo();

                if (!_ipdeets.ContainsKey(isf.IP))
                {
                    _ipdeets[isf.IP] = new List<InterestingSecurityFailure>();
                }
                _ipdeets[isf.IP].Add(isf);
            
                 secfailures = _ipdeets[isf.IP].Count;
            }

            WriteInfo(Invariant($"[Event {isf.EventId}] Count in last hour: [{secfailures}]"));
            WriteInfo(Invariant($"[Event {isf.EventId}] User: [{isf.UserName}] Domain: [{isf.Domain}]"));

            if (secfailures >= SecFailureCountThreshold)
            {
                TryBlockIp(isf.IP);
            }
        }

        /// <summary>
        /// Deletes any stale entries from the dictionary
        /// </summary>
        private void PruneIpInfo()
        {
            var itemstoremove = new List<string>();
            foreach (var entry in _ipdeets)
            {
                entry.Value.RemoveAll(isf => isf.Date < DateTime.Now.AddHours(-1));
                if (entry.Value.Count == 0)
                {
                    itemstoremove.Add(entry.Key);
                }
            }
            foreach (var item in itemstoremove)
            {
                _ipdeets.Remove(item);
            }
        }

        private static void TryBlockIp(string internetAddress)
        {
            try
            {
                BlockIp(internetAddress);
            }
            catch (TypeLoadException e)
            {
                WriteInfo(e.ToString());
                WriteInfo("Failed to run Powershell script!! Is PowerShell 5.1 installed? (WMF 5.1):");
                WriteInfo("https://www.microsoft.com/en-us/download/details.aspx?id=54616");
            }
        }

        public static void ReloadLocalSubnets()
        {
            LocalSubnets = LoadLocalSubnets();
        }
        /// <summary>
        /// Given an IP string, block address using
        /// PowerShell script.
        /// </summary>
        /// <param name="ip"></param>
        /// <exception cref="TypeLoadException">If powershell assemby fails to load. Is Powershell 5.1 installed?</exception>
        private static void BlockIp(string ip)
        {
            var dict = new Dictionary<string, object>
            {
                { "IpAddress", ip }
            };

            WriteInfo($"Calling PowerShell script to block ip {ip}");

            var res = PowerShellHelper.RunPowerShellScript(_blockscript, dict);
            foreach (var e in res.Errors)
            {
                WriteInfo(Invariant($"{e}"));
            }
            foreach (var i in res.Information)
            {
                WriteInfo(Invariant($"{i}"));
            }
        }

        /// <summary>
        ///  Read config file appsetting "LocalSubnets" and return
        ///  list of local subnets.
        /// </summary>
        public static Collection<Subnet> LoadLocalSubnets()
        {
            var sublist = new Collection<Subnet>();

            // add IPv4 link-local subnet
            var ipautosub = new Subnet
            {
                Address = "169.254.0.0",
                MaskBits = 16
            };
            sublist.Add(ipautosub);

            // add subnets from config file
            var subsconfig = ConfigurationManager.AppSettings["LocalSubnets"];
            if (subsconfig == null)
            {
                return sublist;
            }

            var subs = subsconfig.Split(',');
            foreach (var entry in subs)
            {
                Subnet s = null;
                string[] parts = null;
                try
                {
                    parts = entry.Split('/');
                    s = new Subnet()
                    {
                        Address = parts[0],
                        MaskBits = int.Parse(parts[1],CultureInfo.CurrentCulture)
                    };
                }
                catch (ArgumentOutOfRangeException e)
                {
                    WriteInfo($"Failure while parsing LocalSubnets config setting for entry [{entry}]. Error: {e.Message}");
                    continue;
                }
                catch (FormatException)
                {
                    WriteInfo($"Failure while parsing LocalSubnets config setting for entry [{entry}]. Couldn't convert '{parts[1]}' to an int");
                    continue;
                }
                catch (IndexOutOfRangeException)
                {
                    WriteInfo($"Failure while parsing LocalSubnets config setting for entry [{entry}]. Make sure value is in CIDR notation (address/maskbits) for example '18.42.124.13/20'");
                    continue;
                }
                if (s != null)
                    sublist.Add(s);
            }
            return sublist;
        }
    }

    public class InterestingSecurityFailure
    {
        public string IP { get; set; }
        public DateTime? Date { get; set; }
        public string UserName { get; set; }
        public string Domain { get; set; }
        public int EventId { get; set; }
    }
}