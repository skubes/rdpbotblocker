using System;
using System.Management.Automation;
using System.Collections.ObjectModel;
using System.Management.Automation.Runspaces;
using System.Collections.Generic;

namespace TestBedConsole
{
    class Program
    {
        static void Main(string[] args)
        {

            var powershellargs = new Dictionary<string, object>
            {
                { "IpAddress", "1.0.0.0" }
            };
            var script = @"
Write-Output ""yo""";
            RunPowerShellScript(script, powershellargs);
        }

        static Collection<PSObject> RunPowerShellScript(string script, Dictionary<String, Object> parameters)
        {
            Collection<PSObject> objects = new Collection<PSObject>();
            using (RunspacePool rsp = RunspaceFactory.CreateRunspacePool())
            {
                rsp.Open();
                var ps = PowerShell.Create();
                ps.RunspacePool = rsp;
                ps.AddScript(script);
                foreach (var p in parameters)
                {
                    ps.AddParameter(p.Key, p.Value);
                }
                objects = ps.Invoke();

                foreach (var e in ps.Streams.Error)
                {
                    Console.WriteLine($"{e}");
                }

                foreach (var i in ps.Streams.Information)
                {
                    Console.WriteLine($"{i}");
                }
            }
            return objects;
        }
    }
}
