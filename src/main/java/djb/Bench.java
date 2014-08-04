/* Ported from C to Java by Dmitry Skiba [sahn0], 23/02/08.
 * Original: http://cds.xs4all.nl:8081/ecdh/
 */
/* Generic 64-bit integer implementation of Curve25519 ECDH
 * Written by Matthijs van Duin, 200608242056
 * Public domain.
 */
package djb;

import djb.Curve25519;

public class Bench {

	public static void main(String[] arguments) {
		double tk=0,tv=0;
		System.out.println("\n--- Diffie Hellman (ECDH) ---\n");
		benchmark("Key agreement", BENCH_AGREE, 4, 0);
		test_equal(k, check1);
		System.out.println(" Keypair generation : same\n");

		System.out.println("\n--- Digital Signatures (EC-KCDSA) ---\n");
		tv = benchmark("Verification", BENCH_VERIFY, 4, 0);
		test_equal(k, check2);
		tk = benchmark("Keypair generation", BENCH_KEYGEN, 2, tv);
		test_equal(e1k, check3);
		test_equal(e2k, check4);
		benchmark("Signing", BENCH_SIGN, 1, tk + tv);
		test_equal(k, check5);
		System.out.println("\nOK");
	}
	
	///////////////////////////////////////////////////////////////////////////
	
	private static byte[] e1={
		3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	private static byte[] e2={
		5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	private static byte[] k={
		9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	private static byte[] e1k={
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	private static byte[] e2k={
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	private static byte[] e1e2k={
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	private static byte[] e2e1k={
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	private static byte[] e1s={
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	private static byte[] e2s={
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	            	
	private static final void xor25519(byte[] d, byte[] s) {
		int i;
		for (i = 0; i < 32; i++)
			d[i] ^= s[i];
	}
	
	private static final void test_equal(byte[] a, byte[] b) {
		int i;
		for (i = 0; i < 32; i++) {
			if (a[i] != b[i]) {
				System.err.println("\n*** consistency check failed ***\n");
				System.exit(-1);
			}
		}
	}
	
	private static final void state_update() {
		test_equal(e1e2k, e2e1k);
		xor25519(e1, e2k);
		xor25519(e2, e1k);
		xor25519( k, e1e2k);
	}
	
	private static final int
		BENCH_NOP		=0,
		BENCH_AGREE		=1,
		BENCH_VERIFY	=2,
		BENCH_KEYGEN	=3,
		BENCH_SIGN		=4;
	
	private static final long time_bench(int bench,int count) {
		long start=System.nanoTime();
		for (;count!=0;--count) {
			switch (bench) {
				case BENCH_NOP:
				{
					state_update();
					break;
				}
				case BENCH_AGREE:
				{
					Curve25519.curve(  e1k, e1,   k);
					Curve25519.curve(e2e1k, e2, e1k);
					Curve25519.curve(  e2k, e2,   k);
					Curve25519.curve(e1e2k, e1, e2k);
					state_update();
					break;
				}
				case BENCH_VERIFY:
				{
					Curve25519.verify(  e1k, e1, Curve25519.ZERO,   k);
					Curve25519.verify(e2e1k, e2, Curve25519.ZERO, e1k);
					Curve25519.verify(  e2k, e2, Curve25519.ZERO,   k);
					Curve25519.verify(e1e2k, e1, Curve25519.ZERO, e2k);
					state_update();
					break;
				}
				case BENCH_KEYGEN:
				{
					Curve25519.keygen(e1k, e1s, e1);
					Curve25519.keygen(e2k, e2s, e2);
					Curve25519.verify(e1e2k, e1s, k, e1k);
					Curve25519.verify(e2e1k, e2s, k, e2k);
					state_update();
					break;
				}
				case BENCH_SIGN:
				{
					Curve25519.keygen(e1k, e1, e1);
					Curve25519.keygen(e1e2k, null, e2);
					Curve25519.sign(e2k, e1e2k, e2, e1);
					Curve25519.verify(e2e1k, e2k, e1e2k, e1k);
					state_update();
					break;
				}
			}
		}
		return (System.nanoTime()-start)/1000;
	}
	
	static double benchmark(String what, int bench,int div,double offset) {
		final int TRIES=3;
		final int COUNT=2000;
		
		int i;
		double time, leasttime = 1e10;
		System.out.printf(" %-18s : ", what);
		for (i = TRIES; i--!=0; ) {
			time = time_bench(bench, COUNT / div);
			time -= time_bench(BENCH_NOP, COUNT / div);
			
			time = time / (COUNT * 1000) - offset;
			
			if (time < leasttime)
				leasttime = time;
		
			System.out.printf("%.3f ", time);
		}
		
		System.out.println("ms");
		
		return leasttime;
	}
	
	private static final byte[] check1={
		(byte)255,(byte)153,(byte)2,  (byte)78, (byte)126,(byte)231,(byte)146,(byte)145,
		(byte)26, (byte)255,(byte)202,(byte)198,(byte)120,(byte)154,(byte)239,(byte)219,
		(byte)81, (byte)85, (byte)90, (byte)245,(byte)200,(byte)21, (byte)212,(byte)168,
		(byte)212,(byte)173,(byte)200,(byte)134,(byte)193,(byte)134,(byte)40, (byte)59
	};
	private static final byte[] check2={
		(byte)4,  (byte)104,(byte)164,(byte)208,(byte)209,(byte)140,(byte)151,(byte)93,
		(byte)72, (byte)158,(byte)222,(byte)60, (byte)125,(byte)144,(byte)106,(byte)156,
		(byte)92, (byte)147,(byte)23, (byte)242,(byte)55, (byte)205,(byte)177,(byte)40,
		(byte)247,(byte)214,(byte)178,(byte)151,(byte)252,(byte)74, (byte)150,(byte)25
	};
	private static final byte[] check3={
		(byte)102,(byte)104,(byte)149,(byte)19, (byte)117,(byte)243,(byte)84, (byte)43,
		(byte)51, (byte)192,(byte)17, (byte)93, (byte)58, (byte)3,  (byte)64, (byte)149,
		(byte)11, (byte)231,(byte)126,(byte)17, (byte)36, (byte)194,(byte)137,(byte)145,
		(byte)86, (byte)189,(byte)235,(byte)42, (byte)147,(byte)13, (byte)202,(byte)36
	};
	private static final byte[] check4={
		(byte)9,  (byte)207,(byte)229,(byte)5,  (byte)75, (byte)70, (byte)10, (byte)63,
		(byte)222,(byte)112,(byte)123,(byte)118,(byte)148,(byte)64, (byte)234,(byte)30,
		(byte)4,  (byte)222,(byte)173,(byte)25, (byte)192,(byte)20, (byte)77, (byte)125,
		(byte)133,(byte)130,(byte)244,(byte)103,(byte)99, (byte)200,(byte)173,(byte)102
	};
	private static final byte[] check5={
		(byte)71, (byte)17, (byte)254,(byte)189,(byte)183,(byte)208,(byte)95, (byte)116,
		(byte)185,(byte)63, (byte)163,(byte)50, (byte)130,(byte)44, (byte)231,(byte)155,
		(byte)150,(byte)39, (byte)72, (byte)139,(byte)42, (byte)211,(byte)82, (byte)0,
		(byte)249,(byte)172,(byte)10, (byte)191,(byte)147,(byte)50,(byte)100, (byte)101
	};
}
