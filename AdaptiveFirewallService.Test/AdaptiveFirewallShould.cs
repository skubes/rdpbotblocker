using System.Collections.Generic;
using System.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SCAdaptiveFirewall;

namespace AdaptiveFirewallService.Test
{
    [TestClass]
    public class AdaptiveFirewallShould

    {
        [TestMethod]
        public void ClassInstanceShouldConstruct()
        {
            var afs = new AdaptiveFirewall();
            Assert.IsInstanceOfType(afs, typeof(AdaptiveFirewall));
        }

        [DataTestMethod]
        [DataRow("", 0)]
        [DataRow("192.168.1.0/24",1)]
        [DataRow("yo/fucker",0)]
        [DataRow("192.168.1.0/24,192.168.2.0/24",2)]
        public void LoadWithhLocalSubnetsSetting(string setting, int expectedCount)
        {
            ConfigurationManager.AppSettings.Set("LocalSubnets", setting);
            PrivateType afw = new PrivateType(typeof (AdaptiveFirewall));
            afw.InvokeStatic("LoadSubnets");
            var subs = afw.GetStaticField("_subnets") as List<Subnet>;
            Assert.AreEqual(subs.Count, expectedCount);
           
        }
    }
}
