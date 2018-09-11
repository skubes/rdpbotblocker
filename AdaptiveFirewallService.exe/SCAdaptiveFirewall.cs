﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Xml;
using System.Management.Automation;
using System.Collections.ObjectModel;
using IPInfo = System.Collections.Generic.Dictionary<System.String, System.Collections.Generic.List<SCAdaptiveFirewall.AdaptiveFirewall.InterestingSecurityFailure>>;

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

            var logpath = Path.Combine(Path.GetTempPath(), "AdaptiveFirewall.log");
            _log = new StreamWriter(logpath, true)
            {
                AutoFlush = true
            };
        }

        protected override void OnStart(string[] args)
        {
            _seclogwatcher.Enabled = true;
        }

        protected override void OnStop()
        {
            _seclogwatcher.Enabled = false;
        }
        /// <summary>
        /// Writes line of output to diag log in
        /// temp folder
        /// </summary>
        /// <param name="infomessage"></param>
        void WriteInfo(string infomessage)
        {
            _log.WriteLine($"[{DateTime.Now.ToString("o").Replace('T', ' ')}] {infomessage}");
        }

        /// <summary>
        /// Callback method that gets executed when an event is
        /// reported to the subscription.
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
                WriteInfo($"Took [{stopwatch.Elapsed.TotalMilliseconds}] milliseconds to process event");
            }
        }
        /// <summary>
        /// Runs commmands or sripts in a new
        /// PowerShell pipeline.
        /// </summary>
        /// <param name="script"></param>
        /// <param name="parameters"></param>
        /// <returns>A collection of PSObjects that were returned from the script or command</returns>
        public Collection<PSObject> RunPowershellScript(string script, Dictionary<String, Object> parameters)
        {
            using (var instance = PowerShell.Create())
            {
                instance.AddScript(script);
                foreach (var p in parameters)
                {
                    instance.AddParameter(p.Key, p.Value);
                }
                var objects = instance.Invoke();
                if (instance.Streams.Error.Count > 0)
                {
                    foreach (var e in instance.Streams.Error)
                    {
                        WriteInfo($"{e}");
                    }
                }
                return objects;
            }
        }
        /// <summary>
        /// Kicks off handling of interesting events by reading 
        /// metadata from Event XML.
        /// </summary>
        /// <param name="er"></param>
        void ProcessEvent(EventRecord er)
        {
            WriteInfo("Received event from the subscription.");

            var xml = new XmlDocument();
            xml.LoadXml(er.ToXml());
            var ns = new XmlNamespaceManager(xml.NameTable);
            ns.AddNamespace("a", "http://schemas.microsoft.com/win/2004/08/events/event");

            var isf = new InterestingSecurityFailure
            {
                Date = er.TimeCreated,
                Ip = (xml.SelectSingleNode("//a:Data[@Name=\"IpAddress\"]", ns))?.InnerText,
                UserName = (xml.SelectSingleNode("//a:Data[@Name=\"TargetUserName\"]", ns))?.InnerText,
                Domain = (xml.SelectSingleNode("//a:Data[@Name=\"TargetDomainName\"]", ns))?.InnerText
            };

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
        /// Check if blocking is necessary depending on how many 
        /// failed attempts there have been 
        /// </summary>
        /// <param name="isf"></param>
        void BlockIpIfNecessary(InterestingSecurityFailure isf)
        {
            PruneIpInfo();

            if (!_ipdeets.ContainsKey(isf.Ip))
            {
                WriteInfo($"Adding record to dictionary for {isf.Ip}");
                _ipdeets[isf.Ip] = new List<InterestingSecurityFailure>();
            }
            _ipdeets[isf.Ip].Add(isf);
            var failures = _ipdeets[isf.Ip].Count;
            WriteInfo($"IP [{isf.Ip}]. Failure count in last 1 hour [{failures}].");
            WriteInfo($"User [{isf.UserName}]. Domain [{isf.Domain}].");
            if (failures >= FailureCountThreshold)
            {
                WriteInfo($"Need to block ip {isf.Ip}");
                BlockIp(isf.Ip);
            }
        }

        private void PruneIpInfo()
        {
            foreach (var entry in _ipdeets)
            {
                entry.Value.RemoveAll(isf => isf.Date < DateTime.Now.AddHours(-1));
            }
        }

        private void BlockIp(string ip)
        {
            var dict = new Dictionary<string, object>
            {
                { "IpAddress", $"{ip}" }
            };
           RunPowershellScript(_blockscript, dict);

        }

        // TODO: Generalize for private IP ranges
        // instead of my house's range.
        static Regex localAddressRE = new Regex(@"192\.168\.[0-5]\.\d{1,3}",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

        IPInfo _ipdeets = new IPInfo();

        EventLogWatcher _seclogwatcher;
        StreamWriter _log;

        public int FailureCountThreshold { get; set; } = 5;

        public class InterestingSecurityFailure
        {
            public string Ip { get; set; }
            public DateTime? Date { get; set; }
            public string UserName { get; set; }
            public string Domain { get; set; }
        }
 

        string _blockscript = @"
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true)]
            [string] $IpAddress
        )
        function Info {
            Param($InfoMessage)
                Write-Information ""[$(Get-Date -Format 'O')] $InfoMessage""
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
        Set-NetFirewallAddressFilter -InputObject $filter -RemoteAddress $distinctIps";
    }
}
