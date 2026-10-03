package mod.jbk.util;

import mod.alucard.tn.apksigner.ApkSigner;

public class TestkeySignBridge {
    private TestkeySignBridge() {
    }

    // Ký APK bằng testkey với cả ba scheme V1, V2 và V3.
    public static void signWithTestkey(String inputPath, String outputPath) throws Exception {
        new ApkSigner().signWithTestKey(inputPath, outputPath, null);
    }
}
