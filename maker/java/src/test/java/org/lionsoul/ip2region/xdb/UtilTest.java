package org.lionsoul.ip2region.xdb;

import org.junit.Test;

public class UtilTest {

    public static final Log log = Log.getLogger(UtilTest.class).setLevel(Log.DEBUG);

    @Test
    public void testCheckIP() throws InvalidInetAddressException {
        final String[] ips = new String[]{
            "192.168.1.102",
            "219.133.111.87",
            "::",
            "3000::",
            "::1001:ffff",
            "2001:2:0:ffff:ffff:ffff:ffff:ffff",
            "::ffff:114.114.114.114"
        };

        for (String ip : ips) {
            final byte[] ipBytes = Util.parseIP(ip);
            log.debugf("%s(v=%s) => %s", ip, Util.ipArrayString(ipBytes), Util.ipToString(ipBytes));
        }
    }

    @Test
    public void testIpCompare() throws InvalidInetAddressException {
        final String[][] ipPairs = new String[][]{
            {"1.0.0.0", "1.0.0.1"},
            {"192.168.1.101", "192.168.1.90"},
            {"219.133.111.87", "114.114.114.114"},
            {"2000::", "2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
            {"2001:4:112::", "2001:4:112:ffff:ffff:ffff:ffff:ffff"},
            {"ffff::", "2001:4:ffff:ffff:ffff:ffff:ffff:ffff"}
        };

        for (String[] ips : ipPairs) {
            final byte[] ip1 = Util.parseIP(ips[0]);
            final byte[] ip2 = Util.parseIP(ips[1]);
            log.debugf("compare(%s, %s): %d", ips[0], ips[1], Util.ipCompare(ip1, ip2));
        }
    }

    @Test
    public void testIpAddOne() throws InvalidInetAddressException {
        final String[] ips = new String[] {
            "1.0.0.0",
            "192.168.1.255",
            "2000::",
            "255.255.255.254",
            "0.0.0.255",
            "0.255.255.255",
            "1.1.255.255"
        };
        for (String ip : ips) {
            final byte[] ipBytes = Util.parseIP(ip);
            log.debugf("ipAddOne(%s): %s", ip, Util.ipToString(Util.ipAddOne(ipBytes)));
        }
    }

    @Test
    public void testIpSubOne() throws InvalidInetAddressException {
        final String[] ips = new String[] {
            "192.168.1.255",
            "1.0.0.1",
            "1.0.0.0",
            "2.0.0.0",
            "2000::",
            "ffff::",
            "1::1",
        };
        for (String ip : ips) {
            final byte[] ipBytes = Util.parseIP(ip);
            log.debugf("ipSubOne(%s): %s", ip, Util.ipToString(Util.ipSubOne(ipBytes)));
        }
    }
}
