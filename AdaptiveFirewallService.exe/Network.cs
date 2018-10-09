using System;
using System.Net;
using System.Net.Sockets;
using static System.Numerics.BigInteger;
using static System.Globalization.CultureInfo;
using static System.Globalization.NumberStyles;

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
        /// <param name="s"></param>
        /// <returns></returns>
        public static bool IsAddressInSubnet(string ip, Subnet s)
        {
            if (!IPAddress.TryParse(ip, out IPAddress ad))
            {
                return false;
            }

            var networkAddress = s.IPAddressObject;
            var IPAddressBytes = ad.GetAddressBytes();
            var networkAddressBytes = networkAddress.GetAddressBytes();

            byte[] subnetMaskOctets;

            if (networkAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                var mask = Parse("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                    HexNumber, InvariantCulture) << (128 - s.MaskBits);

                subnetMaskOctets = new[]
                {
                    (byte)((mask & Parse("00FF000000000000000000000000000000", HexNumber, InvariantCulture)) >> 120),
                    (byte)((mask & Parse("0000FF0000000000000000000000000000", HexNumber, InvariantCulture)) >> 112),
                    (byte)((mask & Parse("000000FF00000000000000000000000000", HexNumber, InvariantCulture)) >> 104),
                    (byte)((mask & Parse("00000000FF000000000000000000000000", HexNumber, InvariantCulture)) >> 96),
                    (byte)((mask & Parse("0000000000FF0000000000000000000000", HexNumber, InvariantCulture)) >> 88),
                    (byte)((mask & Parse("000000000000FF00000000000000000000", HexNumber, InvariantCulture)) >> 80),
                    (byte)((mask & Parse("00000000000000FF000000000000000000", HexNumber, InvariantCulture)) >> 72),
                    (byte)((mask & Parse("0000000000000000FF0000000000000000", HexNumber, InvariantCulture)) >> 64),
                    (byte)((mask & Parse("000000000000000000FF00000000000000", HexNumber, InvariantCulture)) >> 56),
                    (byte)((mask & Parse("00000000000000000000FF000000000000", HexNumber, InvariantCulture)) >> 48),
                    (byte)((mask & Parse("0000000000000000000000FF0000000000", HexNumber, InvariantCulture)) >> 40),
                    (byte)((mask & Parse("000000000000000000000000FF00000000", HexNumber, InvariantCulture)) >> 32),
                    (byte)((mask & Parse("00000000000000000000000000FF000000", HexNumber, InvariantCulture)) >> 24),
                    (byte)((mask & Parse("0000000000000000000000000000FF0000", HexNumber, InvariantCulture)) >> 16),
                    (byte)((mask & Parse("000000000000000000000000000000FF00", HexNumber, InvariantCulture)) >> 8),
                    (byte)((mask & Parse("00000000000000000000000000000000FF", HexNumber, InvariantCulture)) >> 0),
                };
            }
            else if (networkAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                uint mask = 0xFFFFFFFF << (32 - s.MaskBits);
                subnetMaskOctets = new[]
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

            var subnetMaskAddress = new IPAddress(subnetMaskOctets);
            var subnetMaskAddressBytes = subnetMaskAddress.GetAddressBytes();

            if (IPAddressBytes.Length != subnetMaskAddressBytes.Length
                || networkAddressBytes.Length != IPAddressBytes.Length)
            {
                return false;
            }

            for (int i = 0; i < IPAddressBytes.Length; ++i)
            {
                var addressOctet = IPAddressBytes[i];
                var subnetMaskOctet = subnetMaskAddressBytes[i];
                var networkOctet = networkAddressBytes[i];

                if ((networkOctet & subnetMaskOctet) != (addressOctet & subnetMaskOctet)) return false;
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
