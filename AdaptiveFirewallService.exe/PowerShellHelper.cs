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
        /// <exception cref="TypeLoadException">If powershell assemby fails to load. Is Powershell 5.1 installed?</exception>
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

                    var res = new PSResults();
                    res.ReturnedObjects = objects ?? new Collection<PSObject>();

                    if (instance.Streams.Error.Count > 0)
                    {
                        res.Errors = new ErrorRecord[instance.Streams.Error.Count];
                        instance.Streams.Error.CopyTo(res.Errors, 0);
                    }
                    else
                    {
                        res.Errors = new ErrorRecord[0];
                    }

                    if (instance.Streams.Information.Count > 0)
                    {
                        res.Information = new InformationRecord[instance.Streams.Information.Count];
                        instance.Streams.Information.CopyTo(res.Information, 0);
                    }
                    else
                    {
                        res.Information = new InformationRecord[0];
                    }
                    
                    return res;
                }
                finally
                {
                    instance?.Dispose();
                }
            }
        }
    }

    internal class PSResults
    {
        public Collection<PSObject> ReturnedObjects;
        public ErrorRecord[] Errors;
        public InformationRecord[] Information;
    }
}
