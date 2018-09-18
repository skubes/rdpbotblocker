using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Xml;
using System.Management.Automation;
using System.Collections.ObjectModel;
using IPInfo = System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<SCAdaptiveFirewall.AdaptiveFirewall.InterestingSecurityFailure>>;
using System.Threading;
using System.Management.Automation.Runspaces;

namespace SCAdaptiveFirewall
{
    public partial class AdaptiveFirewall : ServiceBase
    {
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

            var logpath = Path.Combine(Path.GetTempPath(), "AdaptiveFirewall.log");
            _log = new StreamWriter(logpath, true)
            {
                AutoFlush = true
            };
        }

        protected override void OnStart(string[] args)
        {
            _seclogwatcher.Enabled = true;
            _rdplogwatcher.Enabled = true;
        }

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
        void WriteInfo(string infomessage)
        {
            lock (_loglock)
            {
                _log.WriteLine($"[{DateTime.Now.ToString("o").Replace('T',' ')} TID:{Thread.CurrentThread.ManagedThreadId:000}] {infomessage}");
            }
        }

        /// <summary>
        /// Callback method that gets executed when an event is
        /// reported to the subscription. Can be called on
        /// multiple threads.
        /// </summary>
        public void OnEventRecordWritten(object obj,
            EventRecordWrittenEventArgs arg)
        {
            // Make sure there was no error reading the event.
            if (arg.EventRecord != null)
            {
                var stopwatch = new Stopwatch();
                stopwatch.Start();
                ProcessEvent(arg.EventRecord);
                stopwatch.Stop();
                if (stopwatch.Elapsed.TotalMilliseconds > 500)
                {
                    WriteInfo($"Took [{stopwatch.Elapsed.TotalSeconds}] seconds to process event");
                }
                else
                {
                    WriteInfo($"Took [{stopwatch.Elapsed.TotalMilliseconds}] milliseconds to process event");
                }
            }
        }
        /// <summary>
        /// Runs commmands or script in a new
        /// PowerShell pipeline.
        /// </summary>
        /// <param name="script"></param>
        /// <param name="parameters"></param>
        /// <returns>A collection of PSObjects that were returned from the script or command</returns>
        public Collection<PSObject> RunPowershellScript(string script, Dictionary<String, Object> parameters)
        {
            Collection<PSObject> objects;
            using (RunspacePool rsp = RunspaceFactory.CreateRunspacePool())
            {
                rsp.Open();
                PowerShell instance = null;
                try
                {
                    instance = PowerShell.Create();
                    instance.RunspacePool = rsp;
                    instance.AddScript(script);
                    foreach (var p in parameters)
                    {
                        instance.AddParameter(p.Key, p.Value);
                    }
                    objects = instance.Invoke();

                    foreach (var e in instance.Streams.Error)
                    {
                        WriteInfo($"{e}");
                    }

                    foreach (var i in instance.Streams.Information)
                    {
                        WriteInfo($"{i}");
                    }
                }
                finally
                {
                    instance?.Dispose();
                }
            }

            return objects ?? new Collection<PSObject>();
        }
        /// <summary>
        /// Kicks off handling of interesting events by reading 
        /// metadata from Event XML.
        /// </summary>
        /// <param name="er"></param>
        void ProcessEvent(EventRecord er)
        {
            WriteInfo($"Received event {er.Id} from the subscription.");

            var xml = new XmlDocument();
            xml.LoadXml(er.ToXml());
            var ns = new XmlNamespaceManager(xml.NameTable);
            ns.AddNamespace("a", "http://schemas.microsoft.com/win/2004/08/events/event");

            var isf = new InterestingSecurityFailure
            {
                Date = er.TimeCreated,
                EventId = er.Id
            };

            switch (er.Id)
            {
                case 4625:
                    isf.Ip = (xml.SelectSingleNode("//a:Data[@Name=\"IpAddress\"]", ns))?.InnerText;
                    isf.UserName = (xml.SelectSingleNode("//a:Data[@Name=\"TargetUserName\"]", ns))?.InnerText;
                    isf.Domain = (xml.SelectSingleNode("//a:Data[@Name=\"TargetDomainName\"]", ns))?.InnerText;
                    break;
                case 140:
                    isf.Ip = (xml.SelectSingleNode("//a:Data[@Name=\"IPString\"]", ns))?.InnerText;
                    break;
            }

            if (isf.Ip == null)
            {
                WriteInfo("Couldn't read IP address from event.  Nothing to do.");
                return;
            }

            if (IsLocalAddress(isf.Ip))
            {
                WriteInfo($"Local address found [{isf.Ip}]. Skipping.");
                return;
            }

            BlockIpIfNecessary(isf);
        }

        /// <summary>
        /// Given an Ip determine if it is a "local"
        /// ip that should be ignored.  See TODO below..
        /// Hack altert
        /// </summary>
        /// <param name="ip"></param>
        /// <returns></returns>
        static bool IsLocalAddress(string ip)
        {
            return localAddressRE.IsMatch(ip);
        }
        /// <summary>
        /// Check if blocking is necessary depending on event type and
        /// how many failed attempts there have been 
        /// </summary>
        /// <param name="isf"></param>
        void BlockIpIfNecessary(InterestingSecurityFailure isf)
        {
            WriteInfo($"[Event {isf.EventId}] IP: [{isf.Ip}]");
            // just straight up block event 140 ips for now!! as a test:)
            if (isf.EventId == 140)
            {
                BlockIp(isf.Ip);
                return;
            }

            // if event 4625 check number of previous
            // failed attempts in past hour.

            int secfailures;
            lock (_datalock)
            {
                PruneIpInfo();

                if (!_ipdeets.ContainsKey(isf.Ip))
                {
                    _ipdeets[isf.Ip] = new List<InterestingSecurityFailure>();
                }
                _ipdeets[isf.Ip].Add(isf);
            
                 secfailures = _ipdeets[isf.Ip].Count;
            }

            WriteInfo($"[Event {isf.EventId}] Count in last hour: [{secfailures}]");
            WriteInfo($"[Event {isf.EventId}] User: [{isf.UserName}] Domain: [{isf.Domain}]");

            if (secfailures >= SecFailureCountThreshold)
            {
                BlockIp(isf.Ip);
            }
        }

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

        private void BlockIp(string ip)
        {
            var dict = new Dictionary<string, object>
            {
                { "IpAddress", $"{ip}" }
            };
           WriteInfo($"Calling PowerShell script to block ip {ip}");
           RunPowershellScript(_blockscript, dict);
        }

        // TODO: Generalize for private IP ranges
        // instead of my house's range.
        static Regex localAddressRE = new Regex(@"192\.168\.[0-5]\.\d{1,3}|127\.0\.0\.1",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

        IPInfo _ipdeets = new IPInfo();

        readonly EventLogWatcher _seclogwatcher;
        readonly EventLogWatcher _rdplogwatcher;
        readonly Object _datalock = new object();
        readonly Object _loglock = new object();
        readonly StreamWriter _log;

        public int SecFailureCountThreshold { get; } = 5;

        public class InterestingSecurityFailure
        {
            public string Ip { get; set; }
            public DateTime? Date { get; set; }
            public string UserName { get; set; }
            public string Domain { get; set; }
            public int EventId { get; set; }
        }
 
        string _blockscript = @"
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true)]
            [string] $IpAddress
        )
        function Info {
            Param($InfoMessage)
                Write-Information ""{PowerShell script} $InfoMessage""
        }

        $InformationPreference = 'Continue'

        Info ""Getting exising blocked IPs from firewall rule (Block RDP Bots)""
        $filter = Get-NetFirewallRule -DisplayName ""Block RDP Bots"" -ErrorAction Stop | Get-NetFirewallAddressFilter
        $existingIps = $filter.RemoteAddress
        Info ""   found [$($existingIps.Count)] IPs""
        Info ""   done.""

        $distinctIps = New-Object 'Collections.Generic.HashSet[String]'
        $existingIps |
            ForEach-Object {
                $distinctIps.Add($_) | Out-Null
        }
        $distinctIps.Add($IpAddress) | Out-Null
        if ($distinctIps.Count -gt $existingIps.Count) {
             Set-NetFirewallAddressFilter -InputObject $filter -RemoteAddress $distinctIps
        }
";
    }
}
