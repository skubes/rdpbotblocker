using System.Collections.Generic;
using System.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SCAdaptiveFirewall;
using Moq;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System;

namespace AdaptiveFirewallService.Test
{
    [TestClass]
    public class AdaptiveFirewallShould

    {
        AdaptiveFirewall _afw = new AdaptiveFirewall();

        [TestMethod]
        public void ClassInstanceShouldHaveConstructed()
        {
            
            Assert.IsInstanceOfType(_afw, typeof(AdaptiveFirewall));
        }
        
        /// <summary>
        /// Test loading subnets from config file
        /// Different rows test different cases, some
        /// where users incorrectly format
        /// the setting. (Should be CIDR notation)
        /// </summary>
        /// <param name="setting"></param>
        /// <param name="expectedCount"></param>
        [DataTestMethod]
        [DataRow("", 0)]
        [DataRow("192.168.1.0/24",1)]
        [DataRow("2.3/24",1)]
        [DataRow("2.3.2.1/50", 0)]
        [DataRow("192.168.1.0/24,192.168.2.0/24",2)]
        [DataRow("192.168.1.0/24,", 1)]
        [DataRow("192.168.1.0/0,", 0)]
        [DataRow("192.168.1.0/33,", 0)]
        [DataRow("192.168.1111.0/24,", 0)]
        [DataRow("192.168.11.0/,", 0)]
        [DataRow("a;ldkfjs/23h,;lk/xhjsdfg", 0)]
        public void LoadWithhLocalSubnetsSetting(string setting, int expectedCount)
        {
            ConfigurationManager.AppSettings.Set("LocalSubnets", setting);
            PrivateType afw = new PrivateType(typeof (AdaptiveFirewall));
            afw.InvokeStatic("LoadSubnets");
            var subs = afw.GetStaticField("_localsubnets") as List<Subnet>;
            Assert.AreEqual(subs.Count, expectedCount);
           
        }

        [DataTestMethod]
        [DataRow("18.66.50.111","192.168.111.0/31", false)]
        [DataRow("192.168.1.111", "192.168.1.0/24", true)]
        [DataRow("192.168.1.111", "192.168.0.0/24", false)]
        [DataRow("192.168.1.111", "192.168.0.0/24,192.168.1.0/24", true)]
        [DataRow("192.168.0.111", "192.168.0.0/24,192.168.1.0/24", true)]
        public void IsLocalIP(string ip, string setting, bool expected)
        {
            ConfigurationManager.AppSettings.Set("LocalSubnets", setting);
            PrivateType afw = new PrivateType(typeof(AdaptiveFirewall));
            afw.InvokeStatic("LoadSubnets");
            var res = afw.InvokeStatic("IsLocalAddress", new object[] { ip });
            Assert.AreEqual(res, expected);

        }

        [TestMethod]
        public void CorrectlyParseEvent140()
        {
            // setup
            var fs = new FileStream(Path.Combine(Environment.CurrentDirectory, "..\\..\\Test Data\\Event140.xml"),FileMode.Open);
            string xml;
            using (var sr = new StreamReader(fs))
            {
                xml = sr.ReadToEnd();
            }
            var er = new Mock<EventRecord>();
            er.Setup(evtr => evtr.ToXml()).Returns(xml);
            er.SetupGet(evtr => evtr.Id).Returns(140);
            er.SetupGet(evtr => evtr.TimeCreated).Returns(DateTime.Parse("2018-09-27T18:53:35.888226600Z"));

            // process
            var res = _afw.ParseEvent(er.Object);

            // assert
            Assert.AreEqual(140, res.EventId);
            Assert.AreEqual("185.143.223.77", res.IP);
            Assert.AreEqual(DateTime.Parse("2018-09-27T18:53:35.888226600Z"), res.Date);
        }

        [TestMethod]
        public void CorrectlyParseEvent4625()
        {
            // setup
            var fs = new FileStream(Path.Combine(Environment.CurrentDirectory, "..\\..\\Test Data\\Event4625.xml"), FileMode.Open);
            string xml;
            using (var sr = new StreamReader(fs))
            {
                xml = sr.ReadToEnd();
            }
            var er = new Mock<EventRecord>();
            er.Setup(evtr => evtr.ToXml()).Returns(xml);
            er.SetupGet(evtr => evtr.Id).Returns(4625);
            er.SetupGet(evtr => evtr.TimeCreated).Returns(DateTime.Parse("2018-09-28T16:50:56.694245200Z"));

            // process
            var res = _afw.ParseEvent(er.Object);

            // assert
            Assert.AreEqual(4625, res.EventId);
            Assert.AreEqual("192.168.0.106", res.IP);
            Assert.AreEqual(DateTime.Parse("2018-09-28T16:50:56.694245200Z"), res.Date);
        }
    }
}
