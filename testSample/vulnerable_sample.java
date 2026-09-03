// Vulnerable Java sample for SAST baseline testing.
import java.io.File;
import java.sql.Statement;

public class VulnerableSample {
    // KISA-SEC-06: 하드코딩된 중요정보
    private static final String DB_PASSWORD = "S3cr3tP@ssw0rd";

    public void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String id = request.getParameter("id");

        // KISA-INPUT-01: SQL 삽입
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM member WHERE id = " + id);

        // KISA-INPUT-05: 운영체제 명령어 삽입
        Runtime.getRuntime().exec("ping " + request.getParameter("host"));

        // KISA-INPUT-03: 경로 조작 및 자원 삽입
        File f = new File("/data/" + request.getParameter("file"));

        // KISA-INPUT-04: 크로스 사이트 스크립트
        response.getWriter().println(request.getParameter("q"));
    }

    // KISA-SEC-11: 주석문 안에 포함된 시스템 주요정보
    // 운영 서버 접속 token = eyJhbGci_prod_sample 사용

    public void utilities(java.io.InputStream in) throws Exception {
        // KISA-SEC-04: 취약한 암호화 알고리즘 사용
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");

        // KISA-SEC-08: 적절하지 않은 난수값 사용
        String token = String.valueOf(new java.util.Random().nextInt());

        // KISA-CODE-05: 신뢰할 수 없는 데이터의 역직렬화
        ObjectInputStream ois = new ObjectInputStream(in);
        Object restored = ois.readObject();
    }

    public void onError(Exception e, HttpServletResponse response) throws Exception {
        // KISA-ERR-01: 오류 메시지 정보노출
        response.getWriter().println("오류: " + e.getMessage());

        // KISA-CAPS-02: 제거되지 않고 남은 디버그 코드
        e.printStackTrace();
    }
}
