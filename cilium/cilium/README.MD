sudo apt update
sudo apt install -y golang clang llvm libbpf-dev libelf-dev make

cd /tmp
curl -LO https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version

go mod init xdp 
go mod tidy

make clean
make
make build-bpf
make build-go

> ip -br link -- ดูชื่อการ์ดแลน:  จะขึ้น ens3 ไม่ก็ eth0 หรืออื่นๆ  แล้วให้ปรับ ใน cmd -iface=  |

>  [ sudo ./bin/cf-allow-http -iface=ens3 -obj=dist/http_guard_xdp.o -mode=generic ]

-- mode xdp-firewall --
ช้าสุด generic  รองรับมากสุด network card| ถ้าใช้ไม่ได้ก็ ลง iptables สะนะ ฮา ฮา ฮา
เร็วหน่อย native รองรับบาง network card  | ถ้าใช้ [native] ไม่ได้ เปลื่ยนไปใช้ [generic] 
เร็วสุดๆ offload รองรับน้อย network card  | ถ้าใช้ [offload] ไม่ได้เปลื่ยนไปใช้ [native] ถ้าใช้ [native] ไม่ได้ เปลื่ยนไปใช้ [generic]

--------------------------------------------------------------------------------------------------------------------

เพื่อให้ได้ ผลการป้องกันที่สูงสุด  เปิด HTTPDDOS ของcloudflare ด้วย
Security
Enabled | httpddos
Sensitivity=Default || Action=Block || Scope=Global

Security bots
Bot Fight Mode ให้กดเปิดด้วยนะครับ
