⚙️ Hướng dẫn Sử dụng trên Máy mục tiêu
Bỏ qua Execution Policy và thực thi trực tiếp:
powershell -ExecutionPolicy Bypass -File .\win_enum.ps1
Chạy trong môi trường Restricted / Interactive Session:
powershell -ep bypass
. .\win_enum.ps1
Xuất kết quả ra file tùy chỉnh:
.\win_enum.ps1 -OutFile "C:\Users\Public\scan_results.txt"
