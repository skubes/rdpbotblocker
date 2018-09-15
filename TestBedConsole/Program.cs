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
            Collection<PSObject> runPowerShellScript(string script, Dictionary<String, Object> parameters)
            {
                var oprs = RunspaceFactory.CreateOutOfProcessRunspace(TypeTable.LoadDefaultTypeFiles());


                oprs.Open();
                Collection<PSObject> objects;
                using (var instance = PowerShell.Create())
                {
                    instance.Runspace = oprs;
                    instance.AddScript(script);
                    foreach (var p in parameters)
                    {
                        instance.AddParameter(p.Key, p.Value);
                    }
                    objects = instance.Invoke();

                    foreach (var e in instance.Streams.Error)
                    {
                        Console.WriteLine($"{e}");
                    }

                    foreach (var i in instance.Streams.Information)
                    {
                        Console.WriteLine($"{i}");
                    }
                }
                oprs.Dispose();
                return objects;
            }
 
        }
    }
}
