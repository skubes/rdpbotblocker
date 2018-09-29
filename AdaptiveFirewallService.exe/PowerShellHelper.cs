using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace SCAdaptiveFirewall
{
    class PowerShellHelper
    {
        /// <summary>
        /// Runs commmands or script in a new
        /// PowerShell runspace pool.
        /// </summary>
        /// <param name="script"></param>
        /// <param name="parameters"></param>
        /// <returns>PSResults object: A collection of PSObjects that were returned from the script or command, and
        /// the error and information streams.
        /// </returns>
       public static PSResults RunPowerShellScript(string script, Dictionary<String, Object> parameters)
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

                    var res = new PSResults
                    {
                        ReturnedObjects = objects ?? new Collection<PSObject>(),
                        Errors = instance.Streams.Error,
                        Information = instance.Streams.Information
                    };

                    return res;
                }
                finally
                {
                    instance?.Dispose();
                }
            }
        }
    }
    public class PSResults
    {
        public Collection<PSObject> ReturnedObjects { get; set; }
        public PSDataCollection<ErrorRecord> Errors { get; set; }
        public PSDataCollection<InformationRecord> Information { get; set; }
    }
}
