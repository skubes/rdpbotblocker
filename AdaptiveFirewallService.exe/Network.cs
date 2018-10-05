﻿using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace SCAdaptiveFirewall
{
    static class Network
    {
        /// <summary>
        /// Given an ip, subnet address, and number
        /// of mask bits, determine whether ip is in subnet
        /// Derived from example here:
        /// https://stackoverflow.com/questions/1499269/how-to-check-if-an-ip-address-is-within-a-particular-subnet
        /// </summary>
        /// <param name="ip"></param>
        /// <param name="subnetaddress"></param>
        /// <param name="maskbits"></param>
        /// <returns></returns>
        public static bool IsAddressInSubnet(string ip, Subnet s)
        {
            if (!IPAddress.TryParse(ip, out IPAddress ad))
            {
                return false;
            }

            var sad = s.IPAddressObject;
            var adbytes = ad.GetAddressBytes();
            var sadbytes = sad.GetAddressBytes();
            IPAddress mad;
            byte[] madbytes;
            byte[] maskoctets;

            if (sad.AddressFamily == AddressFamily.InterNetworkV6)
            {
                var mask = BigInteger.Parse("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                    NumberStyles.HexNumber) << (128 - s.MaskBits);

                maskoctets = new[]
                {
                    (byte)((mask & BigInteger.Parse("00FF000000000000000000000000000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 120),
                    (byte)((mask & BigInteger.Parse("0000FF0000000000000000000000000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 112),
                    (byte)((mask & BigInteger.Parse("000000FF00000000000000000000000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 104),
                    (byte)((mask & BigInteger.Parse("00000000FF000000000000000000000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 96),
                    (byte)((mask & BigInteger.Parse("0000000000FF0000000000000000000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 88),
                    (byte)((mask & BigInteger.Parse("000000000000FF00000000000000000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 80),
                    (byte)((mask & BigInteger.Parse("00000000000000FF000000000000000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 72),
                    (byte)((mask & BigInteger.Parse("0000000000000000FF0000000000000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 64),
                    (byte)((mask & BigInteger.Parse("000000000000000000FF00000000000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 56),
                    (byte)((mask & BigInteger.Parse("00000000000000000000FF000000000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 48),
                    (byte)((mask & BigInteger.Parse("0000000000000000000000FF0000000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 40),
                    (byte)((mask & BigInteger.Parse("000000000000000000000000FF00000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 32),
                    (byte)((mask & BigInteger.Parse("00000000000000000000000000FF000000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 24),
                    (byte)((mask & BigInteger.Parse("0000000000000000000000000000FF0000", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 16),
                    (byte)((mask & BigInteger.Parse("000000000000000000000000000000FF00", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 8),
                    (byte)((mask & BigInteger.Parse("00000000000000000000000000000000FF", NumberStyles.HexNumber, CultureInfo.InvariantCulture)) >> 0),
                };
            }
            else if (sad.AddressFamily == AddressFamily.InterNetwork)
            {
                uint mask = 0xFFFFFFFF << (32 - s.MaskBits);
                maskoctets = new[]
                {
                    (byte)((mask & 0xFF000000) >> 24),
                    (byte)((mask & 0x00FF0000) >> 16),
                    (byte)((mask & 0x0000FF00) >> 8),
                    (byte)((mask & 0x000000FF) >> 0)
                };
            }
            else
            {
                // subnet address is neither IPv4 or IPv6
                // just get out.
                return false;
            }

            mad = new IPAddress(maskoctets);
            madbytes = mad.GetAddressBytes();

            if (adbytes.Length != madbytes.Length
                || sadbytes.Length != adbytes.Length)
            {
                return false;
            }

            for (int i = 0; i < adbytes.Length; ++i)
            {
                var addressOctet = adbytes[i];
                var subnetOctet = madbytes[i];
                var networkOctet = sadbytes[i];

                if ((networkOctet & subnetOctet) != (addressOctet & subnetOctet)) return false;
            }

            return true;
        }
    }

    public class Subnet
    {
        string _address;
        int _maskbits;

        public string Address
        {
            get { return _address; }
            set
            {
                if (IPAddress.TryParse(value, out IPAddress address))
                {
                    _address = value;
                    IPAddressObject = address;
                }
                else
                {
                    throw new ArgumentOutOfRangeException(nameof(value),
                        value, "IP address string unable to be parsed into an IP.");
                }
            }
        }

        public IPAddress IPAddressObject { get; private set; }

        public int MaskBits
        {
            get { return _maskbits; }
            set
            {
                if (IPAddressObject != null
                    && IPAddressObject.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    if (value >= 0 && value <= 128)
                    {
                        _maskbits = value;
                    }
                    else
                    {
                        throw new ArgumentOutOfRangeException(nameof(value),
                            value, "Subnet mask bits must be between 0 and 128 for IPv6 addresses");
                    }
                }
                else if (IPAddressObject != null
                    && IPAddressObject.AddressFamily == AddressFamily.InterNetwork)
                {
                    if (value >= 0 && value <= 32)
                    {
                        _maskbits = value;
                    }
                    else
                    {
                        throw new ArgumentOutOfRangeException(nameof(value),
                            value, "Subnet mask bits must be between 0 and 32 for IPv4 addresses");
                    }
                }
            }
        }
    }
}
