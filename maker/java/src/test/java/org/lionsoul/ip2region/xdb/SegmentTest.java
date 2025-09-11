package org.lionsoul.ip2region.xdb;

import org.junit.Test;

public class SegmentTest {

    private final static Log log = Log.getLogger(SegmentTest.class).setLevel(Log.DEBUG);

    @Test
    public void testParse() throws Exception {
        final String[] strs = {
            "1.1.0.0|1.3.3.24|中国|广东|深圳|电信",
            "28.201.224.0|29.34.191.255|美国|0|0|0|0",
            "2001:4:112::|2001:4:112:ffff:ffff:ffff:ffff:ffff|德国|黑森|美因河畔法兰克福|专线用户"
        };

        for (final String str : strs) {
            final Segment seg = Segment.parse(str);
            log.debugf("seg: %s", seg.toString());
        }
    }

    @Test
    public void testSplit() throws Exception {
        final String[] t_segs = {
            "1.1.0.0|1.3.3.24|中国|广东|深圳|电信",
            "28.201.224.0|29.34.191.255|美国|0|0|0|0",
            "fec0::|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff|瑞士|弗里堡州||专线用户|IANA"
        };

        for (String str : t_segs) {
            final Segment seg = Segment.parse(str);
            log.infof("segment(%s)->split: ", seg.toString());
            for (final Segment s : seg.split()) {
                log.debugf(s.toString());
            }
        }
    }
}