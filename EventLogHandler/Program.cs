using System;
using System.Xml;
using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using IPInfo = System.Collections.Concurrent.ConcurrentDictionary<System.String, System.Collections.Generic.List<EventLogHandler.InterestingSecurityFailure>>;

class EventLogHandler
{
    static void Main(string[] args)
    {

        // Subscribing to event log 
        // additions

        EventLogWatcher tslogwatcher = null;
        EventLogWatcher seclogwatcher = null;

        try
        {
            // Subscribe to receive event notifications
            // in the RDP event log. The query specifies
            // that only EventID 140 events will be returned.
            var subquery = new EventLogQuery(
                "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", PathType.LogName, "*[System/EventID=140]");

            tslogwatcher = new EventLogWatcher(subquery);

            // Set watcher to listen for the EventRecordWritten
            // event.  When this event happens, the callback method
            // (EventLogEventRead) will be called.
            tslogwatcher.EventRecordWritten +=
                new EventHandler<EventRecordWrittenEventArgs>(
                    EventLogEventRead);

            // Begin subscribing to events the events
            tslogwatcher.Enabled = true;

            // Also subscribe to security event log
            // Logon failure events
            subquery = new EventLogQuery("Security", PathType.LogName, "*[System/EventID=4625]");
            seclogwatcher = new EventLogWatcher(subquery);
            seclogwatcher.EventRecordWritten +=
                new EventHandler<EventRecordWrittenEventArgs>(
                    EventLogEventRead);
            seclogwatcher.Enabled = true;

            WriteInfo("Waiting for events...");
            Console.ReadLine();
        }
        catch (EventLogReadingException e)
        {
            WriteInfo($"Error reading the log: {e.Message}");
        }
        finally
        {
           
            if (tslogwatcher != null)
            {
                // Stop listening to events
                tslogwatcher.Enabled = false;
                tslogwatcher.Dispose();
            }
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
        Console.WriteLine($"[{DateTime.Now.ToString("o")}] {infomessage}");
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
        else
        {
            WriteInfo("The event instance was null.");
        }
    }
    public static void ProcessEvent(EventRecord er) {

        WriteInfo($"Received event {er.Id} from the subscription.");
        WriteInfo($"Description: {er.FormatDescription()}");
        WriteInfo($"Event XML: {er.ToXml()}");
        var xml = new XmlDocument();
        xml.LoadXml(er.ToXml().Replace("xmlns='http://schemas.microsoft.com/win/2004/08/events/event'", ""));

        var ie = new InterestingSecurityFailure
        {
            Date = er.TimeCreated
        };

        switch (er.Id)
        {
            case 140:
                ProcessEvent140(xml,ie);
                break;
            case 4625:
                ProcessEvent4625(xml,ie);
                break;
            
        }

        if (isLocalAddress(ie.Ip)) { return; }

        blockIpIfNecessary(ie.Ip);
    }


    private static void ProcessEvent4625(XmlDocument xml, InterestingSecurityFailure ie)
    {
        ie.Ip = (xml.SelectSingleNode("//Data[@Name=\"IpAddress\"]"))?.InnerText;
        ie.UserName = (xml.SelectSingleNode("//Data[@Name=\"TargetUserName\"]"))?.InnerText;
        ie.Domain = (xml.SelectSingleNode("//Data[@Name=\"TargetDomainName\"]"))?.InnerText;
    }

    private static void ProcessEvent140(XmlDocument xml, InterestingSecurityFailure ie)
    {
        ie.Ip = (xml.SelectSingleNode("//Data[@Name=\"IPString\"]"))?.InnerText;
    }

    public static bool isLocalAddress(string ip)
    {

        return _localAddressRE.IsMatch(ip);

    }

    public static void blockIpIfNecessary(string ip)
    {

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

