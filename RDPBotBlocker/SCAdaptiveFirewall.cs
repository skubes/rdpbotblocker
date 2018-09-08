using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Xml;
using IPInfo = System.Collections.Concurrent.ConcurrentDictionary<System.String, System.Collections.Generic.List<SCAdaptiveFirewall.AdaptiveFirewall.InterestingSecurityFailure>>;

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
                    EventLogEventRead);

            var logpath = Path.Combine(Path.GetTempPath(), "AdaptiveFirewall.log");
            _log = new StreamWriter(logpath,true);
            _log.AutoFlush = true;
        }

        protected override void OnStart(string[] args)
        {
            _seclogwatcher.Enabled = true;
        }

        protected override void OnStop()
        {
            _seclogwatcher.Enabled = false;
        }

        void WriteInfo(string infomessage)
        {
            _log.WriteLine($"[{DateTime.Now.ToString("o").Replace('T', ' ')}] {infomessage}");
        }

        /// <summary>
        /// Callback method that gets executed when an event is
        /// reported to the subscription.
        /// </summary>
        public void EventLogEventRead(object obj,
            EventRecordWrittenEventArgs arg)
        {
            // Make sure there was no error reading the event.
            if (arg.EventRecord != null)
            {
                ProcessEvent(arg.EventRecord);
            }
        }
        void ProcessEvent(EventRecord er)
        {

            WriteInfo($"Received event from the subscription.");

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


        static bool IsLocalAddress(string ip)
        {

            return localAddressRE.IsMatch(ip);

        }

        void BlockIpIfNecessary(InterestingSecurityFailure isf)
        {
            if (!_ipdeets.ContainsKey(isf.Ip))
            {
                WriteInfo($"Adding record to dictionary for {isf.Ip}");
                _ipdeets[isf.Ip] = new List<InterestingSecurityFailure>();
            }
            _ipdeets[isf.Ip].Add(isf);
            var failures = _ipdeets[isf.Ip].Count(e => e.Date > DateTime.Now.AddHours(-24));
            WriteInfo($"IP [{isf.Ip}]. Failure count in last 24 hours [{failures}].");
            WriteInfo($"User [{isf.UserName}]. Domain [{isf.Domain}].");
            if (failures > 1)
            {
                WriteInfo($"Need to block ip {isf.Ip}");
            }


        }

        // TODO: Generalize for private IP ranges
        // instead of my house's range.
        static Regex localAddressRE = new Regex(@"192\.168\.[0-5]\.\d{1,3}",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

        IPInfo _ipdeets = new IPInfo();

        EventLogWatcher _seclogwatcher;
        StreamWriter _log;

        public class InterestingSecurityFailure
        {
            public string Ip { get; set; }
            public DateTime? Date { get; set; }
            public string UserName { get; set; }
            public string Domain { get; set; }
        }
    }
}
