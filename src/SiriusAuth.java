import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.DecimalFormat;

public class SiriusAuth {
    private static String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private String algo;
    private String key;
    private int digits;
    private int key_validity;
    private int temporal_flexibility;
    private SiriusAuth(Builder builder) throws NoSuchAlgorithmException {
        this.algo=builder.algo;
        this.digits=builder.digits;
        this.key=builder.key;
        this.key_validity=builder.key_validity;
        this.temporal_flexibility=builder.temporal_flexibility;
    }
    public static class Builder {
        private String algo = "MD5";
        private int digits=6;
        private String key;
        private int key_length=32;
        private int key_validity=30;
        private int temporal_flexibility=3;

        public Builder Algorithm(String algo) {
            this.algo = algo;
            return this;
        }
        public Builder Digits(int digits){
            this.digits=digits;
            return this;
        }
        public Builder Key(String key){
            this.key=key;
            return this;
        }
        public Builder KeyLength(int length){
            this.key_length=length;
            return this;
        }
        public Builder KeyValidity(int seconds){
            this.key_validity=seconds;
            return this;
        }
        public Builder TemporalFlexibility(int seconds){
            this.temporal_flexibility=seconds;
            return this;
        }
        public SiriusAuth build() throws NoSuchAlgorithmException {
            if(key==null){
                this.key=GenerateKey();
            }
            return new SiriusAuth(this);
        }
        private String GenerateKey() throws NoSuchAlgorithmException {
            SecureRandom secureRandom=new SecureRandom();
            StringBuilder sb= new StringBuilder();
            for(int i=0;i<key_length;i++){
                sb.append(AB.charAt(secureRandom.nextInt(AB.length())));
            }
            return sb.toString();
        }
    }
    public int getTimeBasedPassword() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String temp=hash(hash(key)+hash(String.valueOf(System.currentTimeMillis()/(key_validity*1000))));
        byte[]bytes=temp.getBytes("UTF-8");
        String binary="";
        for(int i=0;i<4;i++){
            binary=binary+Integer.toBinaryString(bytes[i]);
        }
        int number=Integer.parseInt(binary, 2);
        DecimalFormat format = new DecimalFormat("#000000000");
        String formattedNumber = format.format(number%(Math.pow(10,digits)));

        return Integer.parseInt(formattedNumber);
    }
    public int getSpecificTimeBasedPassword(long millis) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String temp=hash(hash(key)+hash(String.valueOf(millis/(key_validity*1000))));
        byte[]bytes=temp.getBytes("UTF-8");
        String binary="";
        for(int i=0;i<4;i++){
            binary=binary+Integer.toBinaryString(bytes[i]);
        }
        int number=Integer.parseInt(binary, 2);
        DecimalFormat format = new DecimalFormat("#000000000");
        String formattedNumber = format.format(number%(Math.pow(10,digits)));

        return Integer.parseInt(formattedNumber);
    }
    public String getAlgorithm(){
        return algo;
    }
    public String getKey(){
        return key;
    }
    private String hash(String code) throws NoSuchAlgorithmException {
        MessageDigest m = MessageDigest.getInstance(algo);
        byte[] data = code.getBytes();
        m.update(data,0,data.length);
        BigInteger i = new BigInteger(1,m.digest());
        return String.format("%1$032X", i);
    }
    public boolean checkValidity(int password) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        if((password==getTimeBasedPassword())||(password==getSpecificTimeBasedPassword(System.currentTimeMillis()-temporal_flexibility))||(password==System.currentTimeMillis()+temporal_flexibility)){
            return true;
        }
        return false;
    }
}
