using System;
using System.Diagnostics.Eventing.Reader;

class SubscribeToEventsExample
{
    static void Main(string[] args)
    {
        EventLogWatcher watcher = null;

        try
        {
            // Subscribe to receive event notifications
            // in the RDP event log. The query specifies
            // that only EventID 140 events will be returned.
            var subscriptionQuery = new EventLogQuery(
                "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", PathType.LogName, "*[System/EventID=140]");

            watcher = new EventLogWatcher(subscriptionQuery);

            // Set watcher to listen for the EventRecordWritten
            // event.  When this event happens, the callback method
            // (EventLogEventRead) will be called.
            watcher.EventRecordWritten +=
                new EventHandler<EventRecordWrittenEventArgs>(
                    EventLogEventRead);

            // Begin subscribing to events the events
            watcher.Enabled = true;

            Console.WriteLine("Waiting for events...");
            Console.ReadLine();
        }
        catch (EventLogReadingException e)
        {
            Console.WriteLine("Error reading the log: {0}", e.Message);
        }
        finally
        {
            // Stop listening to events
            watcher.Enabled = false;

            if (watcher != null)
            {
                watcher.Dispose();
            }
        }
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
            Console.WriteLine("Received event {0} from the subscription.",
               arg.EventRecord.Id);
            Console.WriteLine("Description: {0}", arg.EventRecord.FormatDescription());
        }
        else
        {
            Console.WriteLine("The event instance was null.");
        }
    }
}
