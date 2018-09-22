using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SCAdaptiveFirewall;

namespace AdaptiveFirewallService.Test
{
    [TestClass]
    public class AdaptiveFirewallShould

    {
        [TestMethod]
        public void ClassShouldConstruct()
        {
            var afs = new AdaptiveFirewall();
            Assert.IsInstanceOfType(afs, typeof(AdaptiveFirewall));
        }
    }
}
