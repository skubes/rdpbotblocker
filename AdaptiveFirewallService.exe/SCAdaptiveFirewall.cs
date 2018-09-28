using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.ServiceProcess;
using System.Numerics;
using System.Xml;
using System.Management.Automation;
using System.Collections.ObjectModel;
using IPInfo = System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<SCAdaptiveFirewall.InterestingSecurityFailure>>;
using System.Threading;
using System.Management.Automation.Runspaces;
using System.Configuration;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SCAdaptiveFirewall
{
    public partial class AdaptiveFirewall : ServiceBase
    {
        IPInfo _ipdeets = new IPInfo();
        static readonly Object _loglock;
        static readonly StreamWriter _log;
        readonly EventLogWatcher _seclogwatcher;
        readonly EventLogWatcher _rdplogwatcher;
        readonly Object _datalock = new object();
        static List<Subnet> _localsubnets;
        static string _blockscript = @"
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
        ///  Static constructor
        /// </summary>
        static AdaptiveFirewall()
        {
            _loglock = new object();
            var logpath = Path.Combine(Path.GetTempPath(), "AdaptiveFirewall.log");
            _log = new StreamWriter(logpath, true);
            _log.AutoFlush = true;
            LoadSubnets();
        }

        public int SecFailureCountThreshold { get; } = 5;

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
                _log.WriteLine($"[{DateTime.Now.ToString("o").Replace('T',' ')} TID:{Thread.CurrentThread.ManagedThreadId:000}] {infomessage}");
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
        static Collection<PSObject> RunPowerShellScript(string script, Dictionary<String, Object> parameters)
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
                    if (parameters != null)
                    {
                        foreach (var p in parameters)
                        {
                            instance.AddParameter(p.Key, p.Value);
                        }
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

            var isf = ParseEvent(er);

            if (isf.IP == null)
            {
                WriteInfo("Couldn't read IP address from event.  Nothing to do.");
                return;
            }

            if (IsLocalAddress(isf.IP))
            {
                WriteInfo($"Local address found [{isf.IP}]. Skipping.");
                return;
            }

            BlockIpIfNecessary(isf);
        }

        public InterestingSecurityFailure ParseEvent(EventRecord er)
        {
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
        /// <param name="ip"></param>
        /// <returns></returns>
        static bool IsLocalAddress(string ip)
        {
            foreach (var s in _localsubnets)
            {
                if (IsAddressInSubnet(ip, s))
                {
                    return true;
                }
            }
            return false;
        }
        /// <summary>
        /// Given an ip, subnet address, and number
        /// of mask bits, determine whether ip is in subnet
        /// Found mostly:
        /// https://stackoverflow.com/questions/1499269/how-to-check-if-an-ip-address-is-within-a-particular-subnet
        /// </summary>
        /// <param name="ip"></param>
        /// <param name="subnetaddress"></param>
        /// <param name="maskbits"></param>
        /// <returns></returns>
        private static bool IsAddressInSubnet(string ip, Subnet s)
        {
            if (!IPAddress.TryParse(ip, out IPAddress ad))
            {
                return false;
            }

            var sad = s.IPObject;
            var adbytes = ad.GetAddressBytes();
            var sadbytes = sad.GetAddressBytes();
            IPAddress mad;
            byte[] madbytes;
            byte[] maskoctets;

            if (sad.AddressFamily == AddressFamily.InterNetworkV6)
            {
                var mask = BigInteger.Parse("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                    NumberStyles.HexNumber) << (128 - s.MaskBits);

                maskoctets = new[]
                {
                    (byte)((mask & BigInteger.Parse("00FF000000000000000000000000000000", NumberStyles.HexNumber)) >> 120),
                    (byte)((mask & BigInteger.Parse("0000FF0000000000000000000000000000", NumberStyles.HexNumber)) >> 112),
                    (byte)((mask & BigInteger.Parse("000000FF00000000000000000000000000", NumberStyles.HexNumber)) >> 104),
                    (byte)((mask & BigInteger.Parse("00000000FF000000000000000000000000", NumberStyles.HexNumber)) >> 96),
                    (byte)((mask & BigInteger.Parse("0000000000FF0000000000000000000000", NumberStyles.HexNumber)) >> 88),
                    (byte)((mask & BigInteger.Parse("000000000000FF00000000000000000000", NumberStyles.HexNumber)) >> 80),
                    (byte)((mask & BigInteger.Parse("00000000000000FF000000000000000000", NumberStyles.HexNumber)) >> 72),
                    (byte)((mask & BigInteger.Parse("0000000000000000FF0000000000000000", NumberStyles.HexNumber)) >> 64),
                    (byte)((mask & BigInteger.Parse("000000000000000000FF00000000000000", NumberStyles.HexNumber)) >> 56),
                    (byte)((mask & BigInteger.Parse("00000000000000000000FF000000000000", NumberStyles.HexNumber)) >> 48),
                    (byte)((mask & BigInteger.Parse("0000000000000000000000FF0000000000", NumberStyles.HexNumber)) >> 40),
                    (byte)((mask & BigInteger.Parse("000000000000000000000000FF00000000", NumberStyles.HexNumber)) >> 32),
                    (byte)((mask & BigInteger.Parse("00000000000000000000000000FF000000", NumberStyles.HexNumber)) >> 24),
                    (byte)((mask & BigInteger.Parse("0000000000000000000000000000FF0000", NumberStyles.HexNumber)) >> 16),
                    (byte)((mask & BigInteger.Parse("000000000000000000000000000000FF00", NumberStyles.HexNumber)) >> 8),
                    (byte)((mask & BigInteger.Parse("00000000000000000000000000000000FF", NumberStyles.HexNumber)) >> 0),
                };
            }
            else if (sad.AddressFamily == AddressFamily.InterNetwork)
            {
                uint mask = 0xFFFFFFFF << (32 - s.MaskBits);
                maskoctets = new[]
                {
                    (byte)((mask & 0xFF000000) >> 24),
                    (byte)((mask & 0x00FF0000) >> 16),
                    (byte)((mask & 0x0000FF00) >> 8),
                    (byte)((mask & 0x000000FF) >> 0)
                };
            }
            else
            {
                // subnet address is neither IPv4 or IPv6
                // just get out.
                return false;
            }

            mad = new IPAddress(maskoctets);
            madbytes = mad.GetAddressBytes();

            if (adbytes.Length != madbytes.Length
                || sadbytes.Length != adbytes.Length)
            {
                return false;
            }

            for (int i = 0; i < adbytes.Length; ++i)
            {
                var addressOctet = adbytes[i];
                var subnetOctet = madbytes[i];
                var networkOctet = sadbytes[i];

                if ((networkOctet & subnetOctet) != (addressOctet & subnetOctet)) return false;
            }

            return true;
        }

        /// <summary>
        /// Check if blocking is necessary depending on event type and
        /// how many failed attempts there have been 
        /// </summary>
        /// <param name="isf"></param>
        void BlockIpIfNecessary(InterestingSecurityFailure isf)
        {
            WriteInfo($"[Event {isf.EventId}] IP: [{isf.IP}]");
            // just straight up block event 140 ips for now!! as a test:)
            if (isf.EventId == 140)
            {
                BlockIp(isf.IP);
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

            WriteInfo($"[Event {isf.EventId}] Count in last hour: [{secfailures}]");
            WriteInfo($"[Event {isf.EventId}] User: [{isf.UserName}] Domain: [{isf.Domain}]");

            if (secfailures >= SecFailureCountThreshold)
            {
                BlockIp(isf.IP);
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

        /// <summary>
        /// Given an IP string, block address using
        /// PowerShell script.
        /// </summary>
        /// <param name="ip"></param>
        private static void BlockIp(string ip)
        {
            var dict = new Dictionary<string, object>
            {
                { "IpAddress", $"{ip}" }
            };
           WriteInfo($"Calling PowerShell script to block ip {ip}");
           RunPowerShellScript(_blockscript, dict);
        }

        /// <summary>
        ///  Read config file appsetting "LocalSubnets" and update
        ///  corresponding list of Subnet objects.
        /// </summary>
        private static void LoadSubnets()
        {
            var sublist = new List<Subnet>();
            var subsconfig = ConfigurationManager.AppSettings["LocalSubnets"];
            if (subsconfig == null)
            {
                _localsubnets = sublist;
                return;
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
                    WriteInfo(e.Message);
                    continue;
                }
                catch (FormatException)
                {
                    WriteInfo($"Failure while parsing LocalSubnets config setting. Couldn't convert '{parts[1]}' to an int");
                    continue;
                }
                catch (IndexOutOfRangeException)
                {
                    WriteInfo($"Failure while parsing LocalSubnets config setting. Make sure value in the format Address/maskbits");
                    continue;
                }
                if (s != null)
                    sublist.Add(s);
            }
            _localsubnets = sublist;
        }
    }

    internal class Subnet
    {
        string _address;
        int _maskbits;

        public string Address
        {
            get { return _address; }
            set
            {
                if (IPAddress.TryParse(value, out IPAddress address))
                {
                    _address = value;
                    IPObject = address;
                }
                else
                {
                    throw new ArgumentOutOfRangeException(nameof(value),
                        value, "IP address string unable to be parsed into an IP.");
                }
            }
        }

        public IPAddress IPObject { get; private set; }

        public int MaskBits
        {
            get { return _maskbits; }
            set
            {
                if (IPObject != null 
                    && IPObject.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    if (value > 0 && value < 128)
                    {
                        _maskbits = value;
                    }
                    else
                    {
                        throw new ArgumentOutOfRangeException(nameof(value),
                            value, "Subnet mask bits must be between 1 and 127 for IPv6 addresses");
                    }
                }
                else if (IPObject != null 
                    && IPObject.AddressFamily == AddressFamily.InterNetwork)
                {
                    if (value > 0 && value < 32)
                    {
                        _maskbits = value;
                    }
                    else
                    {
                        throw new ArgumentOutOfRangeException(nameof(value),
                            value, "Subnet mask bits must be between 1 and 31 for IPv4 addresses");
                    }
                }
            }
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
