using System.ComponentModel;
using System.ServiceProcess;

namespace SCAdaptiveFirewall
{
    [RunInstaller(true)]
    public partial class ProjectInstaller : System.Configuration.Install.Installer
    {
        private ServiceInstaller serviceInstaller;
        private ServiceProcessInstaller processInstaller;

        public ProjectInstaller()
        {
            InitializeComponent();
            // Instantiate installers for process and services.
            processInstaller = new ServiceProcessInstaller();
            serviceInstaller = new ServiceInstaller();

            // The services run under the system account.
            processInstaller.Account = ServiceAccount.LocalSystem;

            // The services are started automatically.
            serviceInstaller.StartType = ServiceStartMode.Automatic;

            // ServiceName must equal those on ServiceBase derived classes.
            serviceInstaller.ServiceName = "Adaptive firewall";

            serviceInstaller.Description = "Monitors event log entries to block IP addresses with Windows Firewall after unsuccessful logins.";

            // Add installers to collection. Order is not important.
            Installers.Add(serviceInstaller);
            Installers.Add(processInstaller);
        }
    }
}
