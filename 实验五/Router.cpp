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
pcap_if_t* gptr;//����
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
		printf(" ����в����%d��Ԫ�أ�ԴIP��", this->queueLength+1);
		PrintIP(((IPFrame_t*)(this->first->pkt_data))->ipheader.SourceIP);
		printf(" ���ݰ����ȣ�%d", this->first->len);
	}
	else {
		last->next = new packet;
		last = last->next;
		//temp->next = &p;
		memcpy(last->pkt_data, p.pkt_data, p.len);
		last->len = p.len;
		printf(" ����в����%d��Ԫ�أ�ԴIP��",this->queueLength+1);
		PrintIP(((IPFrame_t*)(last->pkt_data))->ipheader.SourceIP);
		printf(" ���ݰ����ȣ�%d", last->len);
	}
	this->queueLength++;
}

void PacketQueue::deleteElement() {
	if (this->queueLength == 0) {
		printf("������Ԫ�ء��޷�ɾ����\n");
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
	arppakcet.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
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
			cout << "  �������ݰ�ʱ��������"<< endl;
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
	cout << "������Ŀ�����磺" << endl;
	char* ip_address = new char[16];
	cin >> ip_address;
	//inet_pton(AF_INET, ip_address, &(temp->next->DesIP));
	temp->next->DesIP = inet_addr(ip_address);
	cout << "������������������룺" << endl;
	char* netmask=new char[16];
	cin >> netmask;
	//inet_pton(AF_INET, netmask, &(temp->next->NetMask));
	temp->next->NetMask = inet_addr(netmask);
	cout << "��������һ����ַ��" << endl;
	char* nexthop = new char[16];
	cin >> nexthop;
	//inet_pton(AF_INET, nexthop, &(temp->next->NextHop));
	temp->next->NextHop = inet_addr(nexthop);

	
	return;
}

void DeleteRouteItem() {
	cout << "������Ҫɾ����·�ɱ�����" << endl;
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
		printf("����ɾ��Ĭ��·�ɣ�\n");
	}

	return;
}

void PrintRouteItem() {
	RouteItem* temp = RouteTable;
	printf("���    Ŀ������         ��������       ��һ����ַ\n");
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
		cout << "�޷��������ݰ�������������﷨";
	}
	//���ù�����
	if (pcap_setfilter(gpcap_handle, &fcode) < 0)
	{
		cout << "���������ô���";
	};
	while (true) {
		//printf("Receive work\n");
		
		int returnValue = pcap_next_ex(handle, &packet_header, &packet_data);
		//printf("���񵽵����ݰ����ȣ�%d\n", packet_header->len);
		if (returnValue == 0)
			continue;
		if (returnValue == 1) {
			outfile.open("log.txt", ios_base::app);
			outfile << "��Receive Thread��\n";
			printf("�������ݰ�\n");
			if (memcmp(((FrameHeader_t*)packet_data)->SrcMAC,SelfMAC,6) == 0){
				outfile << "�����Լ����������ݰ�\n" ;
				printf("�����Լ����������ݰ�\n");
				continue;
			}
			switch (ntohs(((FrameHeader_t*)packet_data)->FrameType)) {
			case 0x0800:
				if (((IPFrame_t*)packet_data)->ipheader.DestinationIP != SelfIP[0] &&
					((IPFrame_t*)packet_data)->ipheader.DestinationIP != SelfIP[1] &&
					!memcmp(((FrameHeader_t*)packet_data)->DesMAC, SelfMAC, 6)
					) {
					printf("������Ҫת�������ݰ� ");
					outfile << "������Ҫת�������ݰ� ";
					packet* t = new packet;
					memcpy(t->pkt_data, packet_data, packet_header->len);
					t->len = packet_header->len;
					printf("���ݰ����ȣ�%d\n", packet_header->len);
					outfile << "���ݰ����ȣ�"<< packet_header->len <<"\n";
					EnterCriticalSection(&cs);
					pq.addElement(*t);
					LeaveCriticalSection(&cs);
					//printf("Ŀ��IP��");
					//PrintIP(((IPFrame_t*)packet_data)->DestinationIP);
					//printf("  ԴIP��");
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
			outfile << "��Send Thread��\n";
			printf("����һ�ζ���ת������");
			outfile << "����һ�ζ���ת������\n";
			EnterCriticalSection(&cs);
			packet* p = pq.first;
			memcpy(&(p->pkt_data), &(pq.first->pkt_data), pq.first->len);
			p->len = pq.first->len;
			if (((IPFrame_t*)(p->pkt_data))->ipheader.TTL) {
				(((IPFrame_t*)(p->pkt_data))->ipheader.TTL)--;
				memcpy(&((((IPFrame_t*)(p->pkt_data))->FrameHeader).SrcMAC), SelfMAC, 6);
				printf("\n�������ݰ�ԴMAC��");
				PrintMac(((((IPFrame_t*)(p->pkt_data))->FrameHeader).SrcMAC));
				printf("\n");
				DWORD NETNO = (SelfNetMask[0]) & (((IPFrame_t*)(p->pkt_data))->ipheader.DestinationIP);
				RouteItem* temp = RouteTable;
				ARPItem* temparp = ARPTable;
				
				if (!memcmp(&SelfNet[0], &NETNO, 4)) {
					printf("ת��ͬһ�������ݰ� ");
					printf("���ݰ��������磺");
					outfile << "ת��ͬһ�������ݰ� ���ݰ��������磺";
					outfile << NETNO<<"\n";
					PrintIP(NETNO);
					printf("\n");
					while ((temparp != NULL) && (memcmp(&(temparp->IP), &(((IPFrame_t*)(p->pkt_data))->ipheader.DestinationIP), 4))) {
						temparp = temparp->next;
					}
					memcpy(&((((IPFrame_t*)(p->pkt_data))->FrameHeader).DesMAC), &(temparp->MAC), 6);
				}
				else if (!memcmp(&(SelfNet[1]), &NETNO, 4)) {
					printf("ת��ͬһ�������ݰ� ");
					printf("���ݰ��������磺");
					outfile << "ת��ͬһ�������ݰ� ���ݰ��������磺";
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
					printf("ת����ͬ�������ݰ� ");
					printf("���ݰ��������磺");
					outfile << "ת����ͬ�������ݰ� ���ݰ��������磺";
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
						temp = RouteTable;//ָ��Ĭ��·��
					}
					printf("·��Ŀ�����磺");
					PrintIP(temp->DesIP);
					outfile << "·��Ŀ�����磺"<< temp->DesIP<<"\n";
					printf("\n");
					if (!memcmp(&(temparp->IP), &(temp->DesIP), 4)) {
						memcpy(&((((IPFrame_t*)(p->pkt_data))->FrameHeader).DesMAC), temparp->MAC, 6);
					}
					else {
						memcpy(&((((IPFrame_t*)(p->pkt_data))->FrameHeader).DesMAC), temparp->next->MAC, 6);
					}
					
					//memcpy(((ICMPFrame_t*)(p->pkt_data))->fh.DesMAC, temparp->MAC, 6);
					printf("���ݰ�Ŀ��MAC��");
					PrintMac(((((IPFrame_t*)(p->pkt_data))->FrameHeader).DesMAC));
					outfile << "���ݰ�Ŀ��MAC��"<< ((((IPFrame_t*)(p->pkt_data))->FrameHeader).DesMAC) <<"\n";
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
	cout << "����'a'���·�ɱ�����'d'ɾ��·�ɱ�����'p'��ӡ·�ɱ�����'q'�˳�����" << endl;
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
		cout << "����'a'���·�ɱ�����'d'ɾ��·�ɱ�����'p'��ӡ·�ɱ�����'q'�˳�����" << endl;
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
		cout << "��ȡ����ʱ��������:" << errbuf << endl;
		return 0;
	}

	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)
	{
		cout << "����" << index + 1 << "\t" << endl;
		cout << "������Ϣ��" << ptr->description << endl<<endl;
		outfile << "����" << index + 1 << "\t";
		outfile << "������Ϣ��" << ptr->description << "\n";
		index++;
	}
	outfile.close();
	int num;
	cout << "������Ҫ�򿪵������ţ�";
	cin >> num;
	ptr = alldevs;
	for (int i = 1; i < num; i++)
	{
		ptr = ptr->next;
	}
	gptr = ptr;
	outfile.open("log.txt", ios_base::app);
	outfile << "������" << num << "\n";
	outfile.close();
	pcap_t* pcap_handle = pcap_open(ptr->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	gpcap_handle = pcap_handle;
	if (pcap_handle == NULL)
	{
		cout << "������ʱ��������" << errbuf << endl;
		return 0;
	}
	else
	{
		cout << "�ɹ��򿪸�����" << endl;
	}
	int no = 0;
	outfile.open("log.txt", ios_base::app);
	for (a = ptr->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			cout << "  IP��ַ��" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
			cout << "  �������룺" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
			outfile << "  IP��ַ��" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << "\n";
			outfile << "  �������룺" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << "\n";
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
		cout << "�޷��������ݰ�������������﷨";
		pcap_freealldevs(alldevs);
		return 0;
	}
	//���ù�����
	if (pcap_setfilter(pcap_handle, &fcode) < 0)
	{
		cout << "���������ô���";
		pcap_freealldevs(alldevs);
		return 0;
	}

	//��װ����
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//����Ϊ�㲥��ַ255.255.255.255.255.255
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;//����Ϊ�����MAC��ַ66-66-66-66-66-66-66
		ARPFrame.RecvHa[i] = 0;
		ARPFrame.SendHa[i] = 0x66;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);
	ARPFrame.HLen = 6;
	ARPFrame.PLen = 4;
	ARPFrame.Operation = htons(0x0001);//����ΪARP����
	SendIP = ARPFrame.SendIP = htonl(0x888888888888);//ԴIP��ַ����Ϊ����IP��ַ

	pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	cout << "��ȡ������MAC��ַ��ARP�����ͳɹ�" << endl;
	while (true)
	{
		int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
		if (rtn == -1)
		{
			cout << "�������ݰ�ʱ��������" << errbuf << endl;
			return 0;
		}
		else
		{
			if (rtn == 0)
			{
				cout << "û�в������ݱ�" << endl;
			}

			else
			{
				IPPacket = (ARPFrame_t*)pkt_data;
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//ȷ���Ǹղŷ����İ�
				{
					cout << "������MAC��ַ���£�" << endl;
					outfile.open("log.txt", ios_base::app);
					outfile << "��������MAC��ַ��" << *(IPPacket->SendHa) << "\n";
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
	printf("ARP����1��IP:");
	PrintIP(ARPTable->IP);
	printf("  MAC: ");
	PrintMac(ARPTable->MAC);
	printf("\n");
	printf("ARP����2��IP:");
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