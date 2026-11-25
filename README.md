# Công cụ Quản lý KH & CN (bản web riêng)

- `index.html`: công cụ (mã hóa AES-256 ngay trong trình duyệt; không chứa dữ liệu khách hàng).
- `functions/api/[[route]].js`: máy chủ dữ liệu trên Cloudflare Pages Functions + D1. Chỉ lưu dữ liệu đã mã hóa; mọi yêu cầu phải có vé Cloudflare Access hợp lệ (kiểm tra chữ ký), thiếu cấu hình thì từ chối tất cả.
- Cấu hình cần có trên Cloudflare Pages: D1 binding `DB`; biến `TEAM_DOMAIN`, `POLICY_AUD`, `ALLOWED_EMAIL`.
