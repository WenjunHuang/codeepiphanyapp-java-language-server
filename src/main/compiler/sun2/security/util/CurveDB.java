/*
 * Copyright (c) 2006, 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package sun2.security.util;

import java.math.BigInteger;

import java.security.spec.*;

import java.util.*;

/**
 * Repository for well-known Elliptic Curve parameters. It is used by both
 * the SunPKCS11 and SunJSSE code.
 *
 * @since   1.6
 * @author  Andreas Sterbenz
 */
public class CurveDB {
    private static final int P  = 1; // prime curve
    private static final int B  = 2; // binary curve
    private static final int PD = 5; // prime curve, mark as default
    private static final int BD = 6; // binary curve, mark as default

    private static final Map<String,NamedCurve> oidMap =
        new LinkedHashMap<String,NamedCurve>();
    private static final Map<String,NamedCurve> nameMap =
        new HashMap<String,NamedCurve>();
    private static final Map<Integer,NamedCurve> lengthMap =
        new HashMap<Integer,NamedCurve>();

    private static Collection<? extends NamedCurve> specCollection;

    // Used by SunECEntries
    public static Collection<? extends NamedCurve>getSupportedCurves() {
        return specCollection;
    }

    // Return a NamedCurve for the specified OID/name or null if unknown.
    public static NamedCurve lookup(String name) {
        NamedCurve spec = oidMap.get(name);
        if (spec != null) {
            return spec;
        }

        return nameMap.get(name);
    }

    // Return EC parameters for the specified field size. If there are known
    // NIST recommended parameters for the given length, they are returned.
    // Otherwise, if there are multiple matches for the given size, an
    // arbitrary one is returns.
    // If no parameters are known, the method returns null.
    // NOTE that this method returns both prime and binary curves.
    static NamedCurve lookup(int length) {
        return lengthMap.get(length);
    }

    // Convert the given ECParameterSpec object to a NamedCurve object.
    // If params does not represent a known named curve, return null.
    public static NamedCurve lookup(ECParameterSpec params) {
        if ((params instanceof NamedCurve) || (params == null)) {
            return (NamedCurve)params;
        }

        // This is a hack to allow SunJSSE to work with 3rd party crypto
        // providers for ECC and not just SunPKCS11.
        // This can go away once we decide how to expose curve names in the
        // public API.
        // Note that it assumes that the 3rd party provider encodes named
        // curves using the short form, not explicitly. If it did that, then
        // the SunJSSE TLS ECC extensions are wrong, which could lead to
        // interoperability problems.
        int fieldSize = params.getCurve().getField().getFieldSize();
        for (NamedCurve namedCurve : specCollection) {
            // ECParameterSpec does not define equals, so check all the
            // components ourselves.
            // Quick field size check first
            if (namedCurve.getCurve().getField().getFieldSize() != fieldSize) {
                continue;
            }
            if (ECUtil.equals(namedCurve, params)) {
                // everything matches our named curve, return it
                return namedCurve;
            }
        }
        // no match found
        return null;
    }

    private static BigInteger bi(String s) {
        return new BigInteger(s, 16);
    }

    private static void add(KnownOIDs o, int type, String sfield,
            String a, String b, String x, String y, String n, int h) {
        BigInteger p = bi(sfield);
        ECField field;
        if ((type == P) || (type == PD)) {
            field = new ECFieldFp(p);
        } else if ((type == B) || (type == BD)) {
            field = new ECFieldF2m(p.bitLength() - 1, p);
        } else {
            throw new RuntimeException("Invalid type: " + type);
        }

        EllipticCurve curve = new EllipticCurve(field, bi(a), bi(b));
        ECPoint g = new ECPoint(bi(x), bi(y));

        String oid = o.value();
        NamedCurve params = new NamedCurve(o, curve, g, bi(n), h);
        if (oidMap.put(oid, params) != null) {
            throw new RuntimeException("Duplication oid: " + oid);
        }

        for (String cn : params.getNameAndAliases()) {
            if (nameMap.put(cn,
                        params) != null) {
                throw new RuntimeException("Duplication name: " + cn);
            }
        }

        int len = field.getFieldSize();
        if ((type == PD) || (type == BD) || (lengthMap.get(len) == null)) {
            // add entry if none present for this field size or if
            // the curve is marked as a default curve.
            lengthMap.put(len, params);
        }
    }

    static {
        /* SEC2 prime curves */
        add(KnownOIDs.secp112r1, P,
            "DB7C2ABF62E35E668076BEAD208B",
            "DB7C2ABF62E35E668076BEAD2088",
            "659EF8BA043916EEDE8911702B22",
            "09487239995A5EE76B55F9C2F098",
            "A89CE5AF8724C0A23E0E0FF77500",
            "DB7C2ABF62E35E7628DFAC6561C5",
            1);

        add(KnownOIDs.secp112r2, P,
            "DB7C2ABF62E35E668076BEAD208B",
            "6127C24C05F38A0AAAF65C0EF02C",
            "51DEF1815DB5ED74FCC34C85D709",
            "4BA30AB5E892B4E1649DD0928643",
            "adcd46f5882e3747def36e956e97",
            "36DF0AAFD8B8D7597CA10520D04B",
            4);

        add(KnownOIDs.secp128r1, P,
            "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC",
            "E87579C11079F43DD824993C2CEE5ED3",
            "161FF7528B899B2D0C28607CA52C5B86",
            "CF5AC8395BAFEB13C02DA292DDED7A83",
            "FFFFFFFE0000000075A30D1B9038A115",
            1);

        add(KnownOIDs.secp128r2, P,
            "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
            "D6031998D1B3BBFEBF59CC9BBFF9AEE1",
            "5EEEFCA380D02919DC2C6558BB6D8A5D",
            "7B6AA5D85E572983E6FB32A7CDEBC140",
            "27B6916A894D3AEE7106FE805FC34B44",
            "3FFFFFFF7FFFFFFFBE0024720613B5A3",
            4);

        add(KnownOIDs.secp160k1, P,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
            "0000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000007",
            "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB",
            "938CF935318FDCED6BC28286531733C3F03C4FEE",
            "0100000000000000000001B8FA16DFAB9ACA16B6B3",
            1);

        add(KnownOIDs.secp160r1, P,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC",
            "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45",
            "4A96B5688EF573284664698968C38BB913CBFC82",
            "23A628553168947D59DCC912042351377AC5FB32",
            "0100000000000000000001F4C8F927AED3CA752257",
            1);

        add(KnownOIDs.secp160r2, P,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70",
            "B4E134D3FB59EB8BAB57274904664D5AF50388BA",
            "52DCB034293A117E1F4FF11B30F7199D3144CE6D",
            "FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E",
            "0100000000000000000000351EE786A818F3A1A16B",
            1);

        add(KnownOIDs.secp192k1, P,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37",
            "000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000003",
            "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D",
            "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D",
            "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D",
            1);

        add(KnownOIDs.secp192r1, PD,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
            "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
            1);

        add(KnownOIDs.secp224k1, P,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",
            "00000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000005",
            "A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C",
            "7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5",
            "010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7",
            1);

        add(KnownOIDs.secp224r1, PD,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
            "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
            "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
            "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
            1);

        add(KnownOIDs.secp256k1, P,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000007",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            1);

        add(KnownOIDs.secp256r1, PD,
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            1);

        add(KnownOIDs.secp384r1, PD,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
            1);

        add(KnownOIDs.secp521r1, PD,
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
            1);

        /* ANSI X9.62 prime curves */
        add(KnownOIDs.prime192v2, P,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
            "CC22D6DFB95C6B25E49C0D6364A4E5980C393AA21668D953",
            "EEA2BAE7E1497842F2DE7769CFE9C989C072AD696F48034A",
            "6574D11D69B6EC7A672BB82A083DF2F2B0847DE970B2DE15",
            "FFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC80418648D8DD31",
            1);

        add(KnownOIDs.prime192v3, P,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
            "22123DC2395A05CAA7423DAECCC94760A7D462256BD56916",
            "7D29778100C65A1DA1783716588DCE2B8B4AEE8E228F1896",
            "38A90F22637337334B49DCB66A6DC8F9978ACA7648A943B0",
            "FFFFFFFFFFFFFFFFFFFFFFFF7A62D031C83F4294F640EC13",
            1);

        add(KnownOIDs.prime239v1, P,
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC",
            "6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A",
            "0FFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF",
            "7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B",
            1);

        add(KnownOIDs.prime239v2, P,
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC",
            "617FAB6832576CBBFED50D99F0249C3FEE58B94BA0038C7AE84C8C832F2C",
            "38AF09D98727705120C921BB5E9E26296A3CDCF2F35757A0EAFD87B830E7",
            "5B0125E4DBEA0EC7206DA0FC01D9B081329FB555DE6EF460237DFF8BE4BA",
            "7FFFFFFFFFFFFFFFFFFFFFFF800000CFA7E8594377D414C03821BC582063",
            1);

        add(KnownOIDs.prime239v3, P,
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC",
            "255705FA2A306654B1F4CB03D6A750A30C250102D4988717D9BA15AB6D3E",
            "6768AE8E18BB92CFCF005C949AA2C6D94853D0E660BBF854B1C9505FE95A",
            "1607E6898F390C06BC1D552BAD226F3B6FCFE48B6E818499AF18E3ED6CF3",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF975DEB41B3A6057C3C432146526551",
            1);

        /* SEC2 binary curves */
        add(KnownOIDs.sect113r1, B,
            "020000000000000000000000000201",
            "003088250CA6E7C7FE649CE85820F7",
            "00E8BEE4D3E2260744188BE0E9C723",
            "009D73616F35F4AB1407D73562C10F",
            "00A52830277958EE84D1315ED31886",
            "0100000000000000D9CCEC8A39E56F",
            2);

        add(KnownOIDs.sect113r2, B,
            "020000000000000000000000000201",
            "00689918DBEC7E5A0DD6DFC0AA55C7",
            "0095E9A9EC9B297BD4BF36E059184F",
            "01A57A6A7B26CA5EF52FCDB8164797",
            "00B3ADC94ED1FE674C06E695BABA1D",
            "010000000000000108789B2496AF93",
            2);

        add(KnownOIDs.sect131r1, B,
            "080000000000000000000000000000010D",
            "07A11B09A76B562144418FF3FF8C2570B8",
            "0217C05610884B63B9C6C7291678F9D341",
            "0081BAF91FDF9833C40F9C181343638399",
            "078C6E7EA38C001F73C8134B1B4EF9E150",
            "0400000000000000023123953A9464B54D",
            2);

        add(KnownOIDs.sect131r2, B,
            "080000000000000000000000000000010D",
            "03E5A88919D7CAFCBF415F07C2176573B2",
            "04B8266A46C55657AC734CE38F018F2192",
            "0356DCD8F2F95031AD652D23951BB366A8",
            "0648F06D867940A5366D9E265DE9EB240F",
            "0400000000000000016954A233049BA98F",
            2);

        add(KnownOIDs.sect163k1, BD,
            "0800000000000000000000000000000000000000C9",
            "000000000000000000000000000000000000000001",
            "000000000000000000000000000000000000000001",
            "02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8",
            "0289070FB05D38FF58321F2E800536D538CCDAA3D9",
            "04000000000000000000020108A2E0CC0D99F8A5EF",
            2);

        add(KnownOIDs.sect163r1, B,
            "0800000000000000000000000000000000000000C9",
            "07B6882CAAEFA84F9554FF8428BD88E246D2782AE2",
            "0713612DCDDCB40AAB946BDA29CA91F73AF958AFD9",
            "0369979697AB43897789566789567F787A7876A654",
            "00435EDB42EFAFB2989D51FEFCE3C80988F41FF883",
            "03FFFFFFFFFFFFFFFFFFFF48AAB689C29CA710279B",
            2);

        add(KnownOIDs.sect163r2, BD,
            "0800000000000000000000000000000000000000C9",
            "000000000000000000000000000000000000000001",
            "020A601907B8C953CA1481EB10512F78744A3205FD",
            "03F0EBA16286A2D57EA0991168D4994637E8343E36",
            "00D51FBC6C71A0094FA2CDD545B11C5C0C797324F1",
            "040000000000000000000292FE77E70C12A4234C33",
            2);

        add(KnownOIDs.sect193r1, B,
            "02000000000000000000000000000000000000000000008001",
            "0017858FEB7A98975169E171F77B4087DE098AC8A911DF7B01",
            "00FDFB49BFE6C3A89FACADAA7A1E5BBC7CC1C2E5D831478814",
            "01F481BC5F0FF84A74AD6CDF6FDEF4BF6179625372D8C0C5E1",
            "0025E399F2903712CCF3EA9E3A1AD17FB0B3201B6AF7CE1B05",
            "01000000000000000000000000C7F34A778F443ACC920EBA49",
            2);

        add(KnownOIDs.sect193r2, B,
            "02000000000000000000000000000000000000000000008001",
            "0163F35A5137C2CE3EA6ED8667190B0BC43ECD69977702709B",
            "00C9BB9E8927D4D64C377E2AB2856A5B16E3EFB7F61D4316AE",
            "00D9B67D192E0367C803F39E1A7E82CA14A651350AAE617E8F",
            "01CE94335607C304AC29E7DEFBD9CA01F596F927224CDECF6C",
            "010000000000000000000000015AAB561B005413CCD4EE99D5",
            2);

        add(KnownOIDs.sect233k1, BD,
            "020000000000000000000000000000000000000004000000000000000001",
            "000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000001",
            "017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126",
            "01DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3",
            "008000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF",
            4);

        add(KnownOIDs.sect233r1, B,
            "020000000000000000000000000000000000000004000000000000000001",
            "000000000000000000000000000000000000000000000000000000000001",
            "0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD",
            "00FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B",
            "01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052",
            "01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7",
            2);

        add(KnownOIDs.sect239k1, B,
            "800000000000000000004000000000000000000000000000000000000001",
            "000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000001",
            "29A0B6A887A983E9730988A68727A8B2D126C44CC2CC7B2A6555193035DC",
            "76310804F12E549BDB011C103089E73510ACB275FC312A5DC6B76553F0CA",
            "2000000000000000000000000000005A79FEC67CB6E91F1C1DA800E478A5",
            4);

        add(KnownOIDs.sect283k1, BD,
            "0800000000000000000000000000000000000000000000000000000000000000000010A1",
            "000000000000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000000000000000001",
            "0503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836",
            "01CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61",
            4);

        add(KnownOIDs.sect283r1, B,
            "0800000000000000000000000000000000000000000000000000000000000000000010A1",
            "000000000000000000000000000000000000000000000000000000000000000000000001",
            "027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5",
            "05F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B12053",
            "03676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4",
            "03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307",
            2);

        add(KnownOIDs.sect409k1, BD,
            "02000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000001",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            "0060F05F658F49C1AD3AB1890F7184210EFD0987E307C84C27ACCFB8F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE9023746",
            "01E369050B7C4E42ACBA1DACBF04299C3460782F918EA427E6325165E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B",
            "007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF",
            4);

        add(KnownOIDs.sect409r1, B,
            "02000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000001",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            "0021A5C2C8EE9FEB5C4B9A753B7B476B7FD6422EF1F3DD674761FA99D6AC27C8A9A197B272822F6CD57A55AA4F50AE317B13545F",
            "015D4860D088DDB3496B0C6064756260441CDE4AF1771D4DB01FFE5B34E59703DC255A868A1180515603AEAB60794E54BB7996A7",
            "0061B1CFAB6BE5F32BBFA78324ED106A7636B9C5A7BD198D0158AA4F5488D08F38514F1FDF4B4F40D2181B3681C364BA0273C706",
            "010000000000000000000000000000000000000000000000000001E2AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173",
            2);

        add(KnownOIDs.sect571k1, BD,
            "080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000425",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            "026EB7A859923FBC82189631F8103FE4AC9CA2970012D5D46024804801841CA44370958493B205E647DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C8972",
            "0349DC807F4FBF374F4AEADE3BCA95314DD58CEC9F307A54FFC61EFC006D8A2C9D4979C0AC44AEA74FBEBBB9F772AEDCB620B01A7BA7AF1B320430C8591984F601CD4C143EF1C7A3",
            "020000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001",
            4);

        add(KnownOIDs.sect571r1, B,
            "080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000425",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            "02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A",
            "0303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19",
            "037BF27342DA639B6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43BAB08A576291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B",
            "03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47",
            2);

        /* ANSI X9.62 binary curves */
        add(KnownOIDs.c2tnb191v1, B,
            "800000000000000000000000000000000000000000000201",
            "2866537B676752636A68F56554E12640276B649EF7526267",
            "2E45EF571F00786F67B0081B9495A3D95462F5DE0AA185EC",
            "36B3DAF8A23206F9C4F299D7B21A9C369137F2C84AE1AA0D",
            "765BE73433B3F95E332932E70EA245CA2418EA0EF98018FB",
            "40000000000000000000000004A20E90C39067C893BBB9A5",
            2);

        add(KnownOIDs.c2tnb191v2, B,
            "800000000000000000000000000000000000000000000201",
            "401028774D7777C7B7666D1366EA432071274F89FF01E718",
            "0620048D28BCBD03B6249C99182B7C8CD19700C362C46A01",
            "3809B2B7CC1B28CC5A87926AAD83FD28789E81E2C9E3BF10",
            "17434386626D14F3DBF01760D9213A3E1CF37AEC437D668A",
            "20000000000000000000000050508CB89F652824E06B8173",
            4);

        add(KnownOIDs.c2tnb191v3, B,
            "800000000000000000000000000000000000000000000201",
            "6C01074756099122221056911C77D77E77A777E7E7E77FCB",
            "71FE1AF926CF847989EFEF8DB459F66394D90F32AD3F15E8",
            "375D4CE24FDE434489DE8746E71786015009E66E38A926DD",
            "545A39176196575D985999366E6AD34CE0A77CD7127B06BE",
            "155555555555555555555555610C0B196812BFB6288A3EA3",
            6);

        add(KnownOIDs.c2tnb239v1, B,
            "800000000000000000000000000000000000000000000000001000000001",
            "32010857077C5431123A46B808906756F543423E8D27877578125778AC76",
            "790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16",
            "57927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D",
            "61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305",
            "2000000000000000000000000000000F4D42FFE1492A4993F1CAD666E447",
            4);

        add(KnownOIDs.c2tnb239v2, B,
            "800000000000000000000000000000000000000000000000001000000001",
            "4230017757A767FAE42398569B746325D45313AF0766266479B75654E65F",
            "5037EA654196CFF0CD82B2C14A2FCF2E3FF8775285B545722F03EACDB74B",
            "28F9D04E900069C8DC47A08534FE76D2B900B7D7EF31F5709F200C4CA205",
            "5667334C45AFF3B5A03BAD9DD75E2C71A99362567D5453F7FA6E227EC833",
            "1555555555555555555555555555553C6F2885259C31E3FCDF154624522D",
            6);

        add(KnownOIDs.c2tnb239v3, B,
            "800000000000000000000000000000000000000000000000001000000001",
            "01238774666A67766D6676F778E676B66999176666E687666D8766C66A9F",
            "6A941977BA9F6A435199ACFC51067ED587F519C5ECB541B8E44111DE1D40",
            "70F6E9D04D289C4E89913CE3530BFDE903977D42B146D539BF1BDE4E9C92",
            "2E5A0EAF6E5E1305B9004DCE5C0ED7FE59A35608F33837C816D80B79F461",
            "0CCCCCCCCCCCCCCCCCCCCCCCCCCCCCAC4912D2D9DF903EF9888B8A0E4CFF",
            0xA);

        add(KnownOIDs.c2tnb359v1, B,
            "800000000000000000000000000000000000000000000000000000000000000000000000100000000000000001",
            "5667676A654B20754F356EA92017D946567C46675556F19556A04616B567D223A5E05656FB549016A96656A557",
            "2472E2D0197C49363F1FE7F5B6DB075D52B6947D135D8CA445805D39BC345626089687742B6329E70680231988",
            "3C258EF3047767E7EDE0F1FDAA79DAEE3841366A132E163ACED4ED2401DF9C6BDCDE98E8E707C07A2239B1B097",
            "53D7E08529547048121E9C95F3791DD804963948F34FAE7BF44EA82365DC7868FE57E4AE2DE211305A407104BD",
            "01AF286BCA1AF286BCA1AF286BCA1AF286BCA1AF286BC9FB8F6B85C556892C20A7EB964FE7719E74F490758D3B",
            0x4C);

        add(KnownOIDs.c2tnb431r1, B,
            "800000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000001",
            "1A827EF00DD6FC0E234CAF046C6A5D8A85395B236CC4AD2CF32A0CADBDC9DDF620B0EB9906D0957F6C6FEACD615468DF104DE296CD8F",
            "10D9B4A3D9047D8B154359ABFB1B7F5485B04CEB868237DDC9DEDA982A679A5A919B626D4E50A8DD731B107A9962381FB5D807BF2618",
            "120FC05D3C67A99DE161D2F4092622FECA701BE4F50F4758714E8A87BBF2A658EF8C21E7C5EFE965361F6C2999C0C247B0DBD70CE6B7",
            "20D0AF8903A96F8D5FA2C255745D3C451B302C9346D9B7E485E7BCE41F6B591F3E8F6ADDCBB0BC4C2F947A7DE1A89B625D6A598B3760",
            "0340340340340340340340340340340340340340340340340340340323C313FAB50589703B5EC68D3587FEC60D161CC149C1AD4A91",
            0x2760);

        /* ANSI X9.62 binary curves from the 1998 standard but forbidden
         * in the 2005 version of the standard.
         * We don't register them but leave them here for the time being in
         * case we need to support them after all.
         */
/*
        add(KnownOIDs.c2pnb163v1, B,
            "080000000000000000000000000000000000000107",
            "072546B5435234A422E0789675F432C89435DE5242",
            "00C9517D06D5240D3CFF38C74B20B6CD4D6F9DD4D9",
            "07AF69989546103D79329FCC3D74880F33BBE803CB",
            "01EC23211B5966ADEA1D3F87F7EA5848AEF0B7CA9F",
            "0400000000000000000001E60FC8821CC74DAEAFC1",
            2);

        add(KnownOIDs.c2pnb163v2, B,
            "080000000000000000000000000000000000000107",
            "0108B39E77C4B108BED981ED0E890E117C511CF072",
            "0667ACEB38AF4E488C407433FFAE4F1C811638DF20",
            "0024266E4EB5106D0A964D92C4860E2671DB9B6CC5",
            "079F684DDF6684C5CD258B3890021B2386DFD19FC5",
            "03FFFFFFFFFFFFFFFFFFFDF64DE1151ADBB78F10A7",
            2);

        add(KnownOIDs.c2pnb163v3, B,
            "080000000000000000000000000000000000000107",
            "07A526C63D3E25A256A007699F5447E32AE456B50E",
            "03F7061798EB99E238FD6F1BF95B48FEEB4854252B",
            "02F9F87B7C574D0BDECF8A22E6524775F98CDEBDCB",
            "05B935590C155E17EA48EB3FF3718B893DF59A05D0",
            "03FFFFFFFFFFFFFFFFFFFE1AEE140F110AFF961309",
            2);

        add(KnownOIDs.c2pnb176w1, B,
            "0100000000000000000000000000000000080000000007",
            "E4E6DB2995065C407D9D39B8D0967B96704BA8E9C90B",
            "5DDA470ABE6414DE8EC133AE28E9BBD7FCEC0AE0FFF2",
            "8D16C2866798B600F9F08BB4A8E860F3298CE04A5798",
            "6FA4539C2DADDDD6BAB5167D61B436E1D92BB16A562C",
            "00010092537397ECA4F6145799D62B0A19CE06FE26AD",
            0xFF6E);

        add(KnownOIDs.c2pnb208w1, B,
            "010000000000000000000000000000000800000000000000000007",
            "0000000000000000000000000000000000000000000000000000",
            "C8619ED45A62E6212E1160349E2BFA844439FAFC2A3FD1638F9E",
            "89FDFBE4ABE193DF9559ECF07AC0CE78554E2784EB8C1ED1A57A",
            "0F55B51A06E78E9AC38A035FF520D8B01781BEB1A6BB08617DE3",
            "000101BAF95C9723C57B6C21DA2EFF2D5ED588BDD5717E212F9D",
            0xFE48);

        add(KnownOIDs.c2pnb272w1, B,
            "010000000000000000000000000000000000000000000000000000010000000000000B",
            "91A091F03B5FBA4AB2CCF49C4EDD220FB028712D42BE752B2C40094DBACDB586FB20",
            "7167EFC92BB2E3CE7C8AAAFF34E12A9C557003D7C73A6FAF003F99F6CC8482E540F7",
            "6108BABB2CEEBCF787058A056CBE0CFE622D7723A289E08A07AE13EF0D10D171DD8D",
            "10C7695716851EEF6BA7F6872E6142FBD241B830FF5EFCACECCAB05E02005DDE9D23",
            "000100FAF51354E0E39E4892DF6E319C72C8161603FA45AA7B998A167B8F1E629521",
            0xFF06);

        add(KnownOIDs.c2pnb304w1, B,
            "010000000000000000000000000000000000000000000000000000000000000000000000000807",
            "FD0D693149A118F651E6DCE6802085377E5F882D1B510B44160074C1288078365A0396C8E681",
            "BDDB97E555A50A908E43B01C798EA5DAA6788F1EA2794EFCF57166B8C14039601E55827340BE",
            "197B07845E9BE2D96ADB0F5F3C7F2CFFBD7A3EB8B6FEC35C7FD67F26DDF6285A644F740A2614",
            "E19FBEB76E0DA171517ECF401B50289BF014103288527A9B416A105E80260B549FDC1B92C03B",
            "000101D556572AABAC800101D556572AABAC8001022D5C91DD173F8FB561DA6899164443051D",
            0xFE2E);

        add(KnownOIDs.c2pnb368w1, B,
            "0100000000000000000000000000000000000000000000000000000000000000000000002000000000000000000007",
            "E0D2EE25095206F5E2A4F9ED229F1F256E79A0E2B455970D8D0D865BD94778C576D62F0AB7519CCD2A1A906AE30D",
            "FC1217D4320A90452C760A58EDCD30C8DD069B3C34453837A34ED50CB54917E1C2112D84D164F444F8F74786046A",
            "1085E2755381DCCCE3C1557AFA10C2F0C0C2825646C5B34A394CBCFA8BC16B22E7E789E927BE216F02E1FB136A5F",
            "7B3EB1BDDCBA62D5D8B2059B525797FC73822C59059C623A45FF3843CEE8F87CD1855ADAA81E2A0750B80FDA2310",
            "00010090512DA9AF72B08349D98A5DD4C7B0532ECA51CE03E2D10F3B7AC579BD87E909AE40A6F131E9CFCE5BD967",
            0xFF70);
*/

        /*
         * Brainpool curves (RFC 5639)
         * (Twisted curves are not included)
         */

        add(KnownOIDs.brainpoolP160r1, P,
            "E95E4A5F737059DC60DFC7AD95B3D8139515620F",
            "340E7BE2A280EB74E2BE61BADA745D97E8F7C300",
            "1E589A8595423412134FAA2DBDEC95C8D8675E58",
            "BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3",
            "1667CB477A1A8EC338F94741669C976316DA6321",
            "E95E4A5F737059DC60DF5991D45029409E60FC09",
            1);

        add(KnownOIDs.brainpoolP192r1, P,
            "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
            "6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",
            "469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9",
            "C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6",
            "14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F",
            "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1",
            1);

        add(KnownOIDs.brainpoolP224r1, P,
            "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
            "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
            "2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
            "0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",
            "58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",
            "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F",
            1);

        add(KnownOIDs.brainpoolP256r1, P,
            "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
            "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
            "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
            "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
            "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
            "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
            1);

        add(KnownOIDs.brainpoolP320r1, P,
            "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
            "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
            "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
            "43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
            "14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
            "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311",
            1);

        add(KnownOIDs.brainpoolP384r1, P,
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
            "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
            "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
            "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
            "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
            1);

        add(KnownOIDs.brainpoolP512r1, P,
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
            "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
            "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
            "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
            "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
            1);

        specCollection = Collections.unmodifiableCollection(oidMap.values());
    }
}
