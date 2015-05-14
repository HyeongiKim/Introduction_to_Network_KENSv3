/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 *	  Modified: 김현기 20110032, 심영보 20110560
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <list>
namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

/* Open a new socket. It returns filedescriptor (integer) */
void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1_int, int param2_int)
{
	int socket_fd;
	
	socket_fd=this->createFileDescriptor(pid);
	this->returnSystemCall(syscallUUID, socket_fd);
}

/* Close a socket. */
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int param1_int)
{
	this->remove_tcplist(param1_int);
	this->removeFileDescriptor(pid,param1_int);
	this->returnSystemCall(syscallUUID,0);
}

/* Bind a socket. If overlapped, return 1 else 0. */
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int param1_int, struct sockaddr* param2_ptr, socklen_t param3_int)
{
	if (this->check_overlap(param1_int, param2_ptr))
		this->returnSystemCall(syscallUUID,1);
	else 
		this->returnSystemCall(syscallUUID,0);
}

/* Check overlapping. It returns true when there is no overlapping, 
   else add to tcp_list and return false. */
bool TCPAssignment::check_overlap(int fd, sockaddr* addr)
{
	int check_fd;
	uint32_t check_addr;
	unsigned short int check_port;
	std::list<struct tcp_context>::iterator cursor;
	
	struct sockaddr_in* check_sock = (sockaddr_in *)addr;
	check_fd = fd;
	check_addr = check_sock->sin_addr.s_addr;
	check_port = check_sock->sin_port;

	for(cursor=this->tcp_list.begin(); cursor != this->tcp_list.end(); ++cursor)
	{
		/* Already socket_fd exists in tcp_list */
		if((*cursor).socket_fd == check_fd)
			return true;

		/* Bind rule */
		if(( ((*cursor).src_addr == check_addr) || ((*cursor).src_addr == INADDR_ANY) || check_addr == INADDR_ANY )  && ((*cursor).src_port == check_port))
			return true;	
	}
	this->add_tcplist(check_fd, check_addr, check_port);
	return false;
}

/* Get a socket name */
void TCPAssignment::syscall_getsockname(UUID syscallUUID,int pid,int param1_int, struct sockaddr* param2_ptr, socklen_t* param3_ptr)
{
	std::list<struct tcp_context>::iterator sock;
	
	/* Find socket */
	sock = this->find_tcplist(param1_int);
	
	/* The socket_fd (param1_int) does not exist in tcp_list */
	if (sock == this->tcp_list.end())
		this->returnSystemCall(syscallUUID, 1);
	
	((struct sockaddr_in *) param2_ptr)->sin_family = AF_INET;
	((struct sockaddr_in *) param2_ptr)->sin_addr.s_addr = (*sock).src_addr;
	((struct sockaddr_in *) param2_ptr)->sin_port = (*sock).src_port;;
	
	this->returnSystemCall(syscallUUID, 0);
}

/* Listen param1 = sockfd, param2 = backlog */
void TCPAssignment::syscall_listen(UUID syscallUUID,int pid,int fd,int backlog)
{
	printf("-----------------------LISTEN--------------------\nbacklog = %u\n",backlog);
	std::list<struct tcp_context>::iterator sock;
	sock = this->find_tcplist(fd);
	this->backlog = backlog;
	if(!((*sock).is_bound))
		this->returnSystemCall(syscallUUID,1);
	(*sock).tcp_state = E::LISTEN;
	this->returnSystemCall(syscallUUID,0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int param1_int,struct sockaddr* param2_ptr, socklen_t* param3_ptr)
{
	printf("--------------------ACCEPT----------------\n");
	//return false if listen is not called yet
	if(this->find_listen() != param1_int)
		this->returnSystemCall(syscallUUID,1);

	//block the accept call if estb list is empty
	if(this->estb_conn_list.empty())
	{
		//save the accept param
		this->ap_cont.syscallUUID = syscallUUID;
		this->ap_cont.pid = pid;
		this->ap_cont.server_sock_fd = param1_int;
		this->ap_cont.client_addr = param2_ptr;
		ap_cont.client_len = param3_ptr;
		this->accept_cnt++;
		return;
	}
	else
	{
		//pop the established connection and make a new file descriptor
		struct tcp_context estb_conn;
		int socket_fd;
		estb_conn = this->estb_conn_list.front();
		this->estb_conn_list.pop_front();
		socket_fd=this->createFileDescriptor(pid);
		estb_conn.socket_fd = socket_fd;
		((struct sockaddr_in *) param2_ptr)->sin_family = AF_INET;
		((struct sockaddr_in *) param2_ptr)->sin_addr.s_addr = ntohl(estb_conn.src_addr);
		((struct sockaddr_in *) param2_ptr)->sin_port = estb_conn.src_port;
		this->tcp_list.push_back(estb_conn);
		printf("--------------------RETURN1----------------\n");
		this->returnSystemCall(syscallUUID,socket_fd);
	}
}

/* Add new socket block to tcp_list
   Copy socket_fd, addr and port from args to new 'tcp_context sock' */
void TCPAssignment::add_tcplist(int fd, uint32_t addr, unsigned short int port)
{
	tcp_context sock;
	sock.socket_fd = fd;
	sock.src_addr = addr;
	sock.src_port = port;
	sock.is_bound = true;
	
	this->tcp_list.push_back(sock);
}

/* Remove socket from tcp_list */
void TCPAssignment::remove_tcplist(int fd)
{
	std::list<struct tcp_context>::iterator cursor;
	
	cursor=this->tcp_list.begin();
	
	while(cursor != this->tcp_list.end()){
		if ((*cursor).socket_fd == fd)
			cursor=this->tcp_list.erase(cursor);
		else
			++cursor;
	}
}

/* Find a socket. If it does not exist in list, return list.end(). */
std::list<struct tcp_context>::iterator  TCPAssignment::find_tcplist(int fd)
{
	std::list<struct tcp_context>::iterator cursor;
	
	for(cursor=this->tcp_list.begin(); cursor != this->tcp_list.end(); ++cursor){
		if((*cursor).socket_fd == fd)
			return cursor;
	}
	return this->tcp_list.end();
}

/* Find a socket. If it does not exist in list, return list.end(). */
int TCPAssignment::find_listen()
{
	std::list< struct tcp_context >::iterator cursor;

	for(cursor=this->tcp_list.begin(); cursor != this->tcp_list.end(); ++cursor){
		if((*cursor).tcp_state == E::LISTEN)
			return (*cursor).socket_fd;
	}
	return -1;
}

//find connection having seq_num in the pending list
std::list< struct tcp_context >::iterator TCPAssignment::find_conn(int seq_num)
{
	std::list< struct tcp_context >::iterator cursor;
	for(cursor=this->pending_conn_list.begin(); cursor != this->pending_conn_list.end(); ++cursor){
		if(ntohl((*cursor).seq_num) == seq_num)
			return cursor;
	}
	return this->pending_conn_list.end();
}

struct pseudoheader
{
	uint32_t source;
	uint32_t destination;
	uint8_t zero;
	uint8_t protocol;
	uint16_t length;
}__attribute__((packed));

uint16_t TCPAssignment::one_sum(const uint8_t* buffer, size_t size)
{
	bool upper = true;
	uint32_t sum = 0;
	for(size_t k=0; k<size; k++)
	{
		if(upper)
		{
			sum += buffer[k] << 8;
		}
		else
		{
			sum += buffer[k];
		}

		upper = !upper;
	}

	do
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}while((sum & 0xFFFF) != sum);

	return (uint16_t)sum;
}


uint16_t TCPAssignment::tcp_check_sum(uint32_t source, uint32_t dest, const uint8_t* tcp_seg, size_t length)
{
	if(length < 20)
		return 0;
	struct pseudoheader pheader;
	pheader.source = source;
	pheader.destination = dest;
	pheader.zero = 0;
	pheader.protocol = IPPROTO_TCP;
	pheader.length = htons(length);

	uint32_t sum = this->one_sum((uint8_t*)&pheader, sizeof(pheader));
	sum += this->one_sum(tcp_seg, length);

	do
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}while((sum & 0xFFFF) != sum);


	return ~(uint16_t)sum;
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	//Simple L3 forwarding
	//extract address
	uint8_t src_ip[4];
	uint8_t dest_ip[4]; 
	uint8_t src_port[2];
	uint8_t dest_port[2];
	uint8_t IHL[1], tmp[1];
	uint8_t seq_num[4];
	uint8_t ack_num[4];
	uint16_t checksum=0;
	uint8_t tcp_hd[20];
	bool SYN, ACK;
	int sock_fd;
	int tmp_num;
	//struct sockaddr *host_addr = (struct sockaddr *) malloc(sizeof(sockaddr));

	packet->readData(14+12, src_ip, 4); 
	packet->readData(14+16, dest_ip, 4);
	packet->readData(14,IHL,1);
	IHL[0] = IHL[0] & 0x0F;
	packet->readData(14+IHL[0]*4, src_port, 2);
	packet->readData(14+IHL[0]*4+2, dest_port, 2);
	packet->readData(14+IHL[0]*4+4,seq_num,4);
	packet->readData(14+IHL[0]*4+8,ack_num,4);
	packet->readData(14+IHL[0]*4+13, tmp, 1);
	SYN = bool(tmp[0] & 0x2);
	ACK = bool(tmp[0] & 0x10);

	if(SYN && !ACK)//SYN
	{
		//check if the listen is called.
		sock_fd = find_listen();
		if(sock_fd == -1)
		{
			this->freePacket(packet);
			return;
		}
		//check pending list size doesn't exceed backlog value


		if(this->pending_conn_list.size() >= this->backlog)
		{
			this->freePacket(packet);
			return;
		}
		//printf("-------3---------\n");
		//build new connection
		struct tcp_context new_conn;
		new_conn.src_addr = *(uint32_t *)src_ip;
		new_conn.src_port = *(uint16_t *) src_port;
		new_conn.dest_addr = *(uint32_t *) dest_ip;
		new_conn.dest_port = *(uint16_t *) dest_port;
		new_conn.seq_num = htonl(this->seq_num++);
		new_conn.tcp_state = E::SYN_RCVD;
		//push in to pending connection list
		this->pending_conn_list.push_back(new_conn);

		printf("--------------------------------SEQ_NUM-----------------------\nnum: %u\n", ntohl(new_conn.seq_num));

		tmp_num = ntohl(*(int *)seq_num) + 1;
		tmp_num = htonl(tmp_num);
		//Send ACK message
		Packet* SYN_pkt = this->clonePacket(packet);
		SYN_pkt->writeData(14+12, dest_ip, 4);
		SYN_pkt->writeData(14+16, src_ip, 4);
		SYN_pkt->writeData(14+IHL[0]*4, dest_port, 2);
		SYN_pkt->writeData(14+IHL[0]*4+2, src_port, 2);
		SYN_pkt->writeData(14+IHL[0]*4+4, &(new_conn.seq_num),4);
		SYN_pkt->writeData(14+IHL[0]*4+8, &tmp_num,4);
		SYN_pkt->writeData(14+IHL[0]*4+16, &checksum, 2);
		tmp[0] = 0x12;
		SYN_pkt->writeData(14+IHL[0]*4+13, tmp,1);
		SYN_pkt->readData(14+IHL[0]*4,tcp_hd,20);
		checksum = this->tcp_check_sum(*(uint32_t *)src_ip,*(uint32_t *)dest_ip, tcp_hd, 20);
		//printf("--------------------------------FUCK-----------------------\nchecksum = %x\n", checksum);
		checksum = htons(checksum);
		SYN_pkt->writeData(14+IHL[0]*4+16, &checksum, 2);

		this->sendPacket("IPv4", SYN_pkt);
		/*
		Packet* ACK_pkt = this->clonePacket(SYN_pkt);
		ACK_pkt->writeData(14+IHL[0]*4+8, &tmp_num,4);
		tmp[0] = 0x10;
		ACK_pkt->writeData(14+IHL[0]*4+13, tmp,1);
		this->sendPacket("IPv4", ACK_pkt);
		 */

		//printf("------------------Here----------------\nrecieved seqnum: %u SYN: %u\n", ntohl(tmp_num), this->seq_num-1);
	}
	else if(!SYN && ACK)//ACK
	{
		printf("------------------Here----------------\n--------------------------------------\n-------------------------\nACK: %d\n", (int)ack_num[0]);
		std::list<struct tcp_context>::iterator iter;
		struct tcp_context estb_conn;
		//find following connection
		iter = this->find_conn(int(ntohl(*(uint32_t *)ack_num))-1);
		printf("-------------------------------------ACK_NUM------------------------\nack_num: %u", ntohl(*(uint32_t *)ack_num));
		if(iter == this->pending_conn_list.end())
		{
			printf("-------------------ERRORRRRRRR--------------\n");
			this->freePacket(packet);
			return;
		}
		printf("-------------------SUCCESSSSSSSSSSSSSSs--------------\n");
		estb_conn = *iter;
		//move the connection from pending list to estb list
		this->pending_conn_list.erase(iter);
		estb_conn.tcp_state = E::ESTABLISHED;
		this->estb_conn_list.push_back(estb_conn);
		if(this->accept_cnt != 0)
		{
			this->accept_cnt--;
			//pop the established connection and make a new file descriptor
			struct tcp_context finished_conn;
			int socket_fd;
			finished_conn = this->estb_conn_list.front();
			this->estb_conn_list.pop_front();
			socket_fd = this->createFileDescriptor(this->ap_cont.server_sock_fd);
			finished_conn.socket_fd = socket_fd;
			((struct sockaddr_in *) this->ap_cont.client_addr)->sin_family = AF_INET;
			((struct sockaddr_in *) this->ap_cont.client_addr)->sin_addr.s_addr = ntohl(finished_conn.src_addr);
			((struct sockaddr_in *) this->ap_cont.client_addr)->sin_port = finished_conn.src_port;
			this->tcp_list.push_back(finished_conn);
			this->freePacket(packet);
			printf("--------------------RETURN2----------------\n");
			this->returnSystemCall(this->ap_cont.syscallUUID,socket_fd);
		}
	}
	else if(SYN && ACK)//SYNACK
	{
		printf("--------------------------Here2-----------------------\n");
		Packet* myPacket = this->clonePacket(packet); //prepare to send
		//swap src and dest
		myPacket->writeData(14+12, dest_ip, 4);
		myPacket->writeData(14+16, src_ip, 4);
		myPacket->writeData(14+IHL[0]*4, dest_port, 2);
		myPacket->writeData(14+IHL[0]*4+2, src_port, 2);

		//IP module will fill rest of IP header,
		//send it to correct network interface
		this->sendPacket("IPv4", myPacket);
	}
	//given packet is my responsibility
	this->freePacket(packet);
}

void TCPAssignment::timerCallback(void* payload)
{

}


}
