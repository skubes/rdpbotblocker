using Microsoft.VisualStudio.TestTools.UnitTesting;
using SCAdaptiveFirewall;
using System.Collections.Generic;

namespace AdaptiveFirewallService.Test
{
    [TestClass]
    public class PowerShellHelperShould
    {
        [TestMethod]
        public void RunScript()
        {
            var testscript = "Write-Output \"thisisonlyatest\"";
            var res = PowerShellHelper.RunPowerShellScript(testscript, new Dictionary<string, object>());
            Assert.AreEqual(0, res.Errors.Length);
            Assert.AreEqual("thisisonlyatest", res.ReturnedObjects[0]);
        }

        [TestMethod]
        public void ReturnExpectedError()
        {
            // script has typo
            var testscript = "Write-Ouput \"thisisonlyatest\"";
            var res = PowerShellHelper.RunPowerShellScript(testscript, new Dictionary<string, object>());
            Assert.AreEqual(1, res.Errors.Length);
            Assert.AreEqual(0, res.Information.Length);
            Assert.AreEqual(0, res.ReturnedObjects.Count);
        }

        [TestMethod]
        public void ReturnExpectedInformation()
        {
            var testscript = "Write-Information \"thisisonlyatest\"";
            var res = PowerShellHelper.RunPowerShellScript(testscript, new Dictionary<string, object>());
            Assert.AreEqual(0, res.Errors.Length);
            Assert.AreEqual(1, res.Information.Length);
            Assert.AreEqual(0, res.ReturnedObjects.Count);
        }
    }
}
