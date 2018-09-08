using System;
using System.Xml;
using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using IPInfo = System.Collections.Concurrent.ConcurrentDictionary<System.String, System.Collections.Generic.List<EventLogHandler.InterestingSecurityFailure>>;
using System.Collections.Generic;
using System.Linq;

class EventLogHandler
{
    static void Main(string[] args)
    {

        // Subscribing to event log 
        // additions

        EventLogWatcher seclogwatcher = null;

        try
        {
            // Subscribe to security event log
            // Logon failure events
            var subquery = new EventLogQuery("Security",
                PathType.LogName, "*[System/EventID=4625]");

            seclogwatcher = new EventLogWatcher(subquery);
            seclogwatcher.EventRecordWritten +=
                new EventHandler<EventRecordWrittenEventArgs>(
                    EventLogEventRead);
            seclogwatcher.Enabled = true;

            WriteInfo("Waiting for events...");
            Console.ReadLine();
        }
        finally
        {
           
            if (seclogwatcher != null)
            {
                // Stop listening to events
                seclogwatcher.Enabled = false;
                seclogwatcher.Dispose();
            }
        }
    }

    public static void WriteInfo(string infomessage)
    {
        Console.WriteLine($"[{DateTime.Now.ToString("o").Replace('T',' ')}] {infomessage}");
    }

    /// <summary>
    /// Callback method that gets executed when an event is
    /// reported to the subscription.
    /// </summary>
    public static void EventLogEventRead(object obj,
        EventRecordWrittenEventArgs arg)
    {
        // Make sure there was no error reading the event.
        if (arg.EventRecord != null)
        {
            ProcessEvent(arg.EventRecord);         
        }
    }
    public static void ProcessEvent(EventRecord er) {

        WriteInfo($"Received event from the subscription.");

        var xml = new XmlDocument();
        xml.LoadXml(er.ToXml());
        var ns = new XmlNamespaceManager(xml.NameTable);
        ns.AddNamespace("a", "http://schemas.microsoft.com/win/2004/08/events/event");

        var isf = new InterestingSecurityFailure
        {
            Date = er.TimeCreated,
            Ip = (xml.SelectSingleNode("//a:Data[@Name=\"IpAddress\"]", ns)).InnerText,
            UserName = (xml.SelectSingleNode("//a:Data[@Name=\"TargetUserName\"]", ns))?.InnerText,
            Domain = (xml.SelectSingleNode("//a:Data[@Name=\"TargetDomainName\"]", ns))?.InnerText
        };

        if (IsLocalAddress(isf.Ip))
        {
            WriteInfo("Local address found. Skipping.");
            return;
        }

        blockIpIfNecessary(isf);
    }


    public static bool IsLocalAddress(string ip)
    {

        return _localAddressRE.IsMatch(ip);

    }

    public static void blockIpIfNecessary(InterestingSecurityFailure isf)
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
    private static Regex _localAddressRE = new Regex(@"192\.168\.[0-5]\.\d{1,3}",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static IPInfo _ipdeets = new IPInfo();

    public class InterestingSecurityFailure
    {
        public string Ip { get; set; }
        public DateTime? Date { get; set; }
        public string UserName { get; set; }
        public string Domain { get; set; }
    }
}

