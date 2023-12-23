#include <Winsock2.h>
#include<Windows.h>
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>
#include<fstream>
#include <iomanip>

#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning( disable : 4996 )
#define _WINSOCK_DEPRECATED_NO_WARNINGS

using namespace std;

HANDLE hMutex;
HANDLE hReceiverThread;
HANDLE hSenderThread;
HANDLE hRouteOperationThread;

CRITICAL_SECTION cs;
BYTE* SelfMAC = new BYTE[6];
DWORD SelfIP[2] = { {0} };
DWORD SelfNetMask[2] = { {0} };
pcap_t* gpcap_handle;
pcap_if_t* gptr;//网卡
ofstream outfile("log.txt", ios_base::app);

void PrintMac(BYTE MAC[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (i < 5)
			printf("%02x:", MAC[i]);
		else
			printf("%02x", MAC[i]);
	}

};

void PrintIP(DWORD IP)
{
	BYTE* p = (BYTE*)&IP;
	for (int i = 0; i < 3; i++)
	{
		cout<<setw(3)<< dec << (int)*p << ".";
		p++;
	}
	cout << setw(3) << dec << (int)*p;
};

#pragma pack(1)
class ARPItem {
public:
	DWORD IP;
	BYTE MAC[6];
	ARPItem* next;
	ARPItem() {
		this->IP = inet_addr("0.0.0.0");
		this->MAC[0] = this->MAC[1] = this->MAC[2] = this->MAC[3] = this->MAC[4] = this->MAC[5]=0x0;
		this->next=NULL;
	}
	~ARPItem() { delete next; }
};

class RouteItem {
public:
	DWORD DesIP;
	DWORD NetMask;
	DWORD NextHop;
	RouteItem* next;
	int num;
	bool isDefault;
	RouteItem();
	~RouteItem() { delete next; };
};

RouteItem::RouteItem() {
	this->DesIP = 0;
	this->NetMask = 0;
	const char* nexthop = "206.1.2.2";
	this->NextHop = inet_addr(nexthop);
	this->next = NULL;
	this->num = 0;
	this->isDefault = true;
};

class FrameHeader_t {
public:
	BYTE DesMAC[6];
	BYTE SrcMAC[6];
	WORD FrameType;
};

class ARPFrame_t {
public:
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
};

class IPHeader {
public:
	BYTE VersionLen;
	BYTE tos;
	WORD TotalLength;
	WORD Identification;
	WORD FlagOffset;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	DWORD SourceIP;
	DWORD DestinationIP;
};

class IPFrame_t {
public:
	FrameHeader_t FrameHeader;
	IPHeader ipheader;
};
class ICMP {
public:
	BYTE type;
	BYTE code;
	WORD checksum;
	WORD id;
	WORD seq;
	BYTE data[32];
};

class ICMPFrame_t {
public:
	FrameHeader_t fh;
	IPHeader ih;
	ICMP icmp;
};

class packet {
public:
	u_char* pkt_data;
	int len;
	packet* next;
	packet() { pkt_data = new u_char[100]; len = 0; next = NULL; }
	~packet() { delete []pkt_data; next=NULL; }
};
#pragma pack()

class PacketQueue {
public:
	packet* first;
	packet* last;
	int queueLength;
	PacketQueue() { first = new packet;	last = first; queueLength = 0; };
	void addElement(packet& p);
	void deleteElement();
	~PacketQueue() { first=NULL; last=NULL; }
};

void PacketQueue::addElement(packet& p) {
	packet* temp = this->first;
	if (this->queueLength == 0) {
		memcpy(this->first->pkt_data ,p.pkt_data ,p.len);
		this->first->len = p.len;
		//this->first = &p;
		printf(" 向队列插入第%d个元素：源IP：", this->queueLength+1);
		PrintIP(((IPFrame_t*)(this->first->pkt_data))->ipheader.SourceIP);
		printf(" 数据包长度：%d", this->first->len);
	}
	else {
		last->next = new packet;
		last = last->next;
		//temp->next = &p;
		memcpy(last->pkt_data, p.pkt_data, p.len);
		last->len = p.len;
		printf(" 向队列插入第%d个元素：源IP：",this->queueLength+1);
		PrintIP(((IPFrame_t*)(last->pkt_data))->ipheader.SourceIP);
		printf(" 数据包长度：%d", last->len);
	}
	this->queueLength++;
}

void PacketQueue::deleteElement() {
	if (this->queueLength == 0) {
		printf("队列无元素。无法删除！\n");
	}
	else if (this->queueLength == 1) {
		this->first->len = 0;
		this->first->next = NULL;
		this->last = this->first;
		this->queueLength = 0;
	}
	else {
		this->first = this->first->next;
		this->queueLength--;
	}
}

ARPItem* ARPTable = new ARPItem;
PacketQueue pq;

void GetOtherDeviceMac(DWORD IP,BYTE MAC[6]) {
	ARPFrame_t arppakcet;
	memset(arppakcet.FrameHeader.DesMAC, 0xFF, 6);
	memcpy(arppakcet.FrameHeader.SrcMAC, SelfMAC, 6);
	arppakcet.FrameHeader.FrameType = htons(0x0806);
	memset(arppakcet.RecvHa, 0, 6);
	memcpy(arppakcet.SendHa, SelfMAC, 6);
	arppakcet.HLen = 6;
	arppakcet.PLen = 4;
	arppakcet.Operation = htons(0x0001);
	memcpy(&(arppakcet.SendIP), &(SelfIP[0]), 4);
	arppakcet.HardwareType = htons(0x0001);//硬件类型为以太网
	arppakcet.ProtocolType = htons(0x0800);
	memcpy(&(arppakcet.RecvIP), &IP, 4);
	pcap_sendpacket(gpcap_handle, (u_char*)&arppakcet, sizeof(ARPFrame_t));

	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	ARPFrame_t* IPPacket;
	while (true)
	{
		int n = pcap_next_ex(gpcap_handle, &pkt_header, &pkt_data);
		if (n == -1)
		{
			cout << "  捕获数据包时发生错误："<< endl;
			break;
		}
		else
		{
			if (n == 0)
				;
			else
			{
				IPPacket = (ARPFrame_t*)pkt_data;
				if (IPPacket->RecvIP == arppakcet.SendIP && IPPacket->SendIP == arppakcet.RecvIP)
				{
					memcpy(MAC, IPPacket->SendHa, 6);
					break;
				}
			}
		}
	}
}

RouteItem* RouteTable = new RouteItem;

void AddRouteItem() {
	RouteItem* temp = RouteTable;
	while (temp->next != NULL) {
		temp = temp->next;
	}
	temp->next = new RouteItem;
	temp->next->isDefault = false;
	temp->next->num = temp->num + 1;
	cout << "请输入目标网络：" << endl;
	char* ip_address = new char[16];
	cin >> ip_address;
	//inet_pton(AF_INET, ip_address, &(temp->next->DesIP));
	temp->next->DesIP = inet_addr(ip_address);
	cout << "请输入该网络子网掩码：" << endl;
	char* netmask=new char[16];
	cin >> netmask;
	//inet_pton(AF_INET, netmask, &(temp->next->NetMask));
	temp->next->NetMask = inet_addr(netmask);
	cout << "请输入下一跳地址：" << endl;
	char* nexthop = new char[16];
	cin >> nexthop;
	//inet_pton(AF_INET, nexthop, &(temp->next->NextHop));
	temp->next->NextHop = inet_addr(nexthop);

	
	return;
}

void DeleteRouteItem() {
	cout << "请输入要删除的路由表项编号" << endl;
	int o = 0;
	cin >> o;
	RouteItem* temp = RouteTable;
	if (o != 0) {
		for (int i = 0; i < o - 1; i++) {
			temp = temp->next;
		};
		if (temp->next->next != NULL) {
			temp->next = temp->next->next;
		}
		else {
			temp->next = NULL;
		}
		temp = RouteTable;
		while (temp->next != NULL) {
			temp->next->num = temp->num + 1;
			temp = temp->next;
		}
	}
	else {
		printf("不能删除默认路由！\n");
	}

	return;
}

void PrintRouteItem() {
	RouteItem* temp = RouteTable;
	printf("编号    目标网络         子网掩码       下一跳地址\n");
	while (temp != NULL) {
		printf("%d   ", temp->num);
		PrintIP(temp->DesIP);
		printf("  ");
		PrintIP(temp->NetMask);
		printf("  ");
		PrintIP(temp->NextHop);
		printf("\n");
		temp = temp->next;
	}
	printf("\n");
	return;
}

void Receive(pcap_t* handle) {
	pcap_pkthdr* packet_header = nullptr;
	const u_char* packet_data = nullptr;
	u_int netmask;
	netmask = ((sockaddr_in*)(gptr->addresses->netmask))->sin_addr.S_un.S_addr;
	bpf_program fcode;
	if (pcap_compile(gpcap_handle, &fcode, "icmp", 1, netmask) < 0)
	{
		cout << "无法编译数据包过滤器。检查语法";
	}
	//设置过滤器
	if (pcap_setfilter(gpcap_handle, &fcode) < 0)
	{
		cout << "过滤器设置错误";
	};
	while (true) {
		//printf("Receive work\n");
		
		int returnValue = pcap_next_ex(handle, &packet_header, &packet_data);
		//printf("捕获到的数据包长度：%d\n", packet_header->len);
		if (returnValue == 0)
			continue;
		if (returnValue == 1) {
			outfile.open("log.txt", ios_base::app);
			outfile << "【Receive Thread】\n";
			printf("捕获到数据包\n");
			if (memcmp(((FrameHeader_t*)packet_data)->SrcMAC,SelfMAC,6) == 0){
				outfile << "捕获到自己发出的数据包\n" ;
				printf("捕获到自己发出的数据包\n");
				continue;
			}
			switch (ntohs(((FrameHeader_t*)packet_data)->FrameType)) {
			case 0x0800:
				if (((IPFrame_t*)packet_data)->ipheader.DestinationIP != SelfIP[0] &&
					((IPFrame_t*)packet_data)->ipheader.DestinationIP != SelfIP[1] &&
					!memcmp(((FrameHeader_t*)packet_data)->DesMAC, SelfMAC, 6)
					) {
					printf("捕获到需要转发的数据包 ");
					outfile << "捕获到需要转发的数据包 ";
					packet* t = new packet;
					memcpy(t->pkt_data, packet_data, packet_header->len);
					t->len = packet_header->len;
					printf("数据包长度：%d\n", packet_header->len);
					outfile << "数据包长度："<< packet_header->len <<"\n";
					EnterCriticalSection(&cs);
					pq.addElement(*t);
					LeaveCriticalSection(&cs);
					//printf("目标IP：");
					//PrintIP(((IPFrame_t*)packet_data)->DestinationIP);
					//printf("  源IP：");
					//PrintIP(((IPFrame_t*)packet_data)->SourceIP);
					printf("\n\n");
					packet_data = NULL;
					packet_header = NULL;
				}
			}
			outfile << "\n";
			outfile.close();
		}
		else if (returnValue == -1) {
			printf("Error while reading the packets: %s\n", pcap_geterr(handle));
			//break;
		}
	}
	pcap_freecode(&fcode);
	return;
}

uint16_t ipchecksum(u_char* packet, int size){
	((IPFrame_t*)packet)->ipheader.Checksum = 0;
	int count = (size + 1) / 2;
	u_long sum = 0;
	WORD* p = (WORD*)&(((IPFrame_t*)packet)->ipheader);
	while (count--) {
		sum += *p++;
		if (sum & 0xffff0000) {
			sum &= 0xffff;
			sum++;
		}
	}
	return static_cast<uint16_t>(~sum);
}

uint16_t icmppchecksum(const u_char* packet, int size) {
	((ICMPFrame_t*)packet)->icmp.checksum = 0;
	int count = (size + 1) / 2;
	u_long sum = 0;
	while (count--) {
		sum += *packet++;
		if (sum & 0xffff0000) {
			sum &= 0xffff;
			sum++;
		}
	}
	return static_cast<uint16_t>(~sum);
}

void Send(pcap_t* handle) {
	DWORD SelfNet[2];
	SelfNet[0] = SelfIP[0] & SelfNetMask[0];
	SelfNet[1] = SelfIP[1] & SelfNetMask[1];
	//PrintIP(SelfNet[0]);
	//PrintIP(SelfNet[1]);
	while (true) {
		//printf("Send work\n");
		EnterCriticalSection(&cs);
		int num = pq.queueLength;
		LeaveCriticalSection(&cs);
		while (num--) {
			outfile.open("log.txt", ios_base::app);
			outfile << "【Send Thread】\n";
			printf("进行一次队列转发操作");
			outfile << "进行一次队列转发操作\n";
			EnterCriticalSection(&cs);
			packet* p = pq.first;
			memcpy(&(p->pkt_data), &(pq.first->pkt_data), pq.first->len);
			p->len = pq.first->len;
			if (((IPFrame_t*)(p->pkt_data))->ipheader.TTL) {
				(((IPFrame_t*)(p->pkt_data))->ipheader.TTL)--;
				memcpy(&((((IPFrame_t*)(p->pkt_data))->FrameHeader).SrcMAC), SelfMAC, 6);
				printf("\n更改数据包源MAC：");
				PrintMac(((((IPFrame_t*)(p->pkt_data))->FrameHeader).SrcMAC));
				printf("\n");
				DWORD NETNO = (SelfNetMask[0]) & (((IPFrame_t*)(p->pkt_data))->ipheader.DestinationIP);
				RouteItem* temp = RouteTable;
				ARPItem* temparp = ARPTable;
				
				if (!memcmp(&SelfNet[0], &NETNO, 4)) {
					printf("转发同一网段数据包 ");
					printf("数据包处于网络：");
					outfile << "转发同一网段数据包 数据包处于网络：";
					outfile << NETNO<<"\n";
					PrintIP(NETNO);
					printf("\n");
					while ((temparp != NULL) && (memcmp(&(temparp->IP), &(((IPFrame_t*)(p->pkt_data))->ipheader.DestinationIP), 4))) {
						temparp = temparp->next;
					}
					memcpy(&((((IPFrame_t*)(p->pkt_data))->FrameHeader).DesMAC), &(temparp->MAC), 6);
				}
				else if (!memcmp(&(SelfNet[1]), &NETNO, 4)) {
					printf("转发同一网段数据包 ");
					printf("数据包处于网络：");
					outfile << "转发同一网段数据包 数据包处于网络：";
					outfile << NETNO << "\n";
					PrintIP(NETNO);
					printf("\n");
					temparp = ARPTable;
					while ((temparp != NULL) && (memcmp(&(temparp->IP), &(((IPFrame_t*)(p->pkt_data))->ipheader.DestinationIP), 4))) {
						temparp = temparp->next;
					}
					memcpy(&((((IPFrame_t*)(p->pkt_data))->FrameHeader).DesMAC), &(temparp->MAC), 6);
				}
				else {
					temparp = ARPTable;
					printf("转发不同网段数据包 ");
					printf("数据包处于网络：");
					outfile << "转发不同网段数据包 数据包处于网络：";
					outfile << NETNO << "\n";
					PrintIP(NETNO);
					printf("\n");
					while (temp != NULL) {
						if (!memcmp(&(temp->DesIP), &NETNO, 4)) {
							break;
						}
						else
							temp = temp->next;
					}
					if (temp == NULL) {
						temp = RouteTable;//指回默认路由
					}
					printf("路由目标网络：");
					PrintIP(temp->DesIP);
					outfile << "路由目标网络："<< temp->DesIP<<"\n";
					printf("\n");
					if (!memcmp(&(temparp->IP), &(temp->DesIP), 4)) {
						memcpy(&((((IPFrame_t*)(p->pkt_data))->FrameHeader).DesMAC), temparp->MAC, 6);
					}
					else {
						memcpy(&((((IPFrame_t*)(p->pkt_data))->FrameHeader).DesMAC), temparp->next->MAC, 6);
					}
					
					//memcpy(((ICMPFrame_t*)(p->pkt_data))->fh.DesMAC, temparp->MAC, 6);
					printf("数据包目的MAC：");
					PrintMac(((((IPFrame_t*)(p->pkt_data))->FrameHeader).DesMAC));
					outfile << "数据包目的MAC："<< ((((IPFrame_t*)(p->pkt_data))->FrameHeader).DesMAC) <<"\n";
					printf("\n");
				
				}
				((IPFrame_t*)(p->pkt_data))->ipheader.Checksum = ipchecksum((p->pkt_data), 20);
				pcap_sendpacket(gpcap_handle, (p->pkt_data), p->len);
				pq.deleteElement();
			}
			else {
				continue;
			}
			LeaveCriticalSection(&cs);
			printf("\n");
			outfile.close();
		}
		Sleep(200);
	}
	return;
}

void RouteOperation() {
	char c = 's';
	cout << "输入'a'添加路由表、输入'd'删除路由表、输入'p'打印路由表、输入'q'退出程序" << endl;
	cin >> c;
	while (c != 'q') {
		switch (c) {
		case 'a':
			AddRouteItem();
			break;
		case 'd':
			DeleteRouteItem();
			break;
		case 'p':
			PrintRouteItem();
			break;
		default:
			break;
		}
		cout << "输入'a'添加路由表、输入'd'删除路由表、输入'p'打印路由表、输入'q'退出程序" << endl;
		cin >> c;
	}
	exit(0);
	return;
}

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* ptr;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];
	ARPFrame_t ARPFrame;
	ARPFrame_t* IPPacket;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;

	int index = 0;
	DWORD SendIP;
	DWORD RevIP;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		cout << "获取网卡时发生错误:" << errbuf << endl;
		return 0;
	}

	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)
	{
		cout << "网卡" << index + 1 << "\t" << endl;
		cout << "描述信息：" << ptr->description << endl<<endl;
		outfile << "网卡" << index + 1 << "\t";
		outfile << "描述信息：" << ptr->description << "\n";
		index++;
	}
	outfile.close();
	int num;
	cout << "请输入要打开的网卡号：";
	cin >> num;
	ptr = alldevs;
	for (int i = 1; i < num; i++)
	{
		ptr = ptr->next;
	}
	gptr = ptr;
	outfile.open("log.txt", ios_base::app);
	outfile << "打开网卡" << num << "\n";
	outfile.close();
	pcap_t* pcap_handle = pcap_open(ptr->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	gpcap_handle = pcap_handle;
	if (pcap_handle == NULL)
	{
		cout << "打开网卡时发生错误：" << errbuf << endl;
		return 0;
	}
	else
	{
		cout << "成功打开该网卡" << endl;
	}
	int no = 0;
	outfile.open("log.txt", ios_base::app);
	for (a = ptr->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			cout << "  IP地址：" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
			cout << "  子网掩码：" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
			outfile << "  IP地址：" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << "\n";
			outfile << "  子网掩码：" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << "\n";
			memcpy(SelfIP + no, &((struct sockaddr_in*)(a->addr))->sin_addr, 4);
			memcpy(SelfNetMask + no, &((struct sockaddr_in*)(a->netmask))->sin_addr, 4);
			RevIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
		no++;
	}
	outfile.close();
	cout << endl;

	u_int netmask;
	netmask = ((sockaddr_in*)(ptr->addresses->netmask))->sin_addr.S_un.S_addr;
	bpf_program fcode;
	char packet_filter[] = "ether proto \\arp";
	if (pcap_compile(pcap_handle, &fcode, packet_filter, 1, netmask) < 0)
	{
		cout << "无法编译数据包过滤器。检查语法";
		pcap_freealldevs(alldevs);
		return 0;
	}
	//设置过滤器
	if (pcap_setfilter(pcap_handle, &fcode) < 0)
	{
		cout << "过滤器设置错误";
		pcap_freealldevs(alldevs);
		return 0;
	}

	//组装报文
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//设置为广播地址255.255.255.255.255.255
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;//设置为虚拟的MAC地址66-66-66-66-66-66-66
		ARPFrame.RecvHa[i] = 0;
		ARPFrame.SendHa[i] = 0x66;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);
	ARPFrame.HLen = 6;
	ARPFrame.PLen = 4;
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	SendIP = ARPFrame.SendIP = htonl(0x888888888888);//源IP地址设置为虚拟IP地址

	pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	cout << "获取该网卡MAC地址：ARP请求发送成功" << endl;
	while (true)
	{
		int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
		if (rtn == -1)
		{
			cout << "捕获数据包时发生错误：" << errbuf << endl;
			return 0;
		}
		else
		{
			if (rtn == 0)
			{
				cout << "没有捕获到数据报" << endl;
			}

			else
			{
				IPPacket = (ARPFrame_t*)pkt_data;
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//确保是刚才发出的包
				{
					cout << "打开网卡MAC地址如下：" << endl;
					outfile.open("log.txt", ios_base::app);
					outfile << "打开网卡的MAC地址：" << *(IPPacket->SendHa) << "\n";
					outfile.close();
					PrintMac(IPPacket->SendHa);
					memcpy(SelfMAC, IPPacket->SendHa, 6);
					cout << endl;
					break;
				}
			}
		}
	}
	const char ip1[16] = "206.1.1.2";
	DWORD IP1 = inet_addr(ip1);
	GetOtherDeviceMac(IP1, ARPTable->MAC);
	memcpy(&(ARPTable->IP), &IP1, 4);
	ARPTable->next = new ARPItem;
	const char ip2[16] = "206.1.2.2";
	DWORD IP2 = inet_addr(ip2);
	GetOtherDeviceMac(IP2, ARPTable->next->MAC);
	memcpy(&(ARPTable->next->IP),&IP2, 4);
	pcap_freecode(&fcode);
	printf("ARP表项1：IP:");
	PrintIP(ARPTable->IP);
	printf("  MAC: ");
	PrintMac(ARPTable->MAC);
	printf("\n");
	printf("ARP表项2：IP:");
	PrintIP(ARPTable->next->IP);
	printf("  MAC: ");
	PrintMac(ARPTable->next->MAC);
	printf("\n");
	//hMutex = CreateMutex(NULL, FALSE, NULL);
	InitializeCriticalSection(&cs);

	DWORD receiveThreadId;
	hReceiverThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Receive, pcap_handle, 0, &receiveThreadId);
	SetThreadPriority(hReceiverThread, THREAD_PRIORITY_HIGHEST);

	DWORD sendThreadId;
	hSenderThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Send, pcap_handle, 0, &sendThreadId);
	SetThreadPriority(hSenderThread, THREAD_PRIORITY_NORMAL);

	DWORD routeOperationThreadId;
	hRouteOperationThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RouteOperation, NULL, 0,&routeOperationThreadId);
	SetThreadPriority(hRouteOperationThread, THREAD_PRIORITY_LOWEST);

	WaitForSingleObject(hReceiverThread, INFINITE);
	WaitForSingleObject(hSenderThread, INFINITE);
	WaitForSingleObject(hRouteOperationThread, INFINITE);

	//CloseHandle(hMutex);
	CloseHandle(hReceiverThread);
	CloseHandle(hSenderThread);
	CloseHandle(hRouteOperationThread);
	DeleteCriticalSection(&cs);
	pcap_close(pcap_handle);

	delete[] SelfMAC;
	delete[] SelfIP;
	system("pause");
	return 0;
}