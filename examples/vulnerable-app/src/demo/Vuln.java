package demo;
import java.sql.*;
import java.io.*;
import javax.xml.parsers.*;
import org.w3c.dom.Document;
import java.net.URL;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Vuln {
    // SQLi: string concat
    public void query(String user, Connection c) throws Exception {
        Statement st = c.createStatement();
        st.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
    }

    // Command injection
    public void shell(String arg) throws Exception {
        Runtime.getRuntime().exec("ping " + arg);
    }

    // XXE
    public Document loadXml(byte[] d) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        return f.newDocumentBuilder().parse(new ByteArrayInputStream(d));
    }

    // Path traversal
    public byte[] read(String p) throws Exception {
        return new FileInputStream("/data/" + p).readAllBytes();
    }

    // Insecure deserialization
    public Object deser(byte[] d) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(d)).readObject();
    }

    // Weak crypto (MD5-ish via DES/ECB)
    public Cipher weak() throws Exception {
        SecretKey k = SecretKeyFactory.getInstance("DES").generateSecret(new javax.crypto.spec.SecretKeySpec(new byte[8], "DES"));
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    // Hardcoded secret
    private static final String API_KEY = "sk_live_1234567890abcdef";
    private static final String DB_PASS = "Admin@123";

    // SSRF
    public String fetch(String url) throws Exception {
        return new String(new URL(url).openStream().readAllBytes());
    }
}
