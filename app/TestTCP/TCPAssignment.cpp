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
#include <E/Networking/E_RoutingInfo.hpp>
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
        this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
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
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
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
	std::list< struct tcp_context >::iterator iter = find_tcplist(param1_int,pid);
	if(iter == tcp_list.end())
		this->returnSystemCall(syscallUUID,1);
	if(iter->tcp_state == E::ESTABLISHED)
	{
		//fprintf(stderr,"syscall_close: ESTABLISHED\n");
		uint8_t tmp;
		uint16_t checksum=0;
		uint8_t tcp_hd[20];
		int seq_num;
		Packet* FIN_pkt = this->allocatePacket(54);
		FIN_pkt->writeData(14+12, &(iter->src_addr), 4);
		FIN_pkt->writeData(14+16, &(iter->dest_addr), 4);
		FIN_pkt->writeData(14+20, &(iter->src_port), 2);
		FIN_pkt->writeData(14+20+2, &(iter->dest_port), 2);
		seq_num = htonl(this->seq_num);
		FIN_pkt->writeData(14+20+4, &seq_num,4);
		tmp = 0x50;
		FIN_pkt->writeData(14+20+12, &tmp, 1);
		tmp = 0x1;
		FIN_pkt->writeData(14+20+13, &tmp, 1);
		FIN_pkt->readData(14+20,tcp_hd,20);
		checksum = this->tcp_check_sum(iter->src_addr,iter->dest_addr, tcp_hd, 20);
		checksum = htons(checksum);
		FIN_pkt->writeData(14+20+16, &checksum, 2);
		this->sendPacket("IPv4",FIN_pkt);
		iter->seq_num = this->seq_num++;
		iter->tcp_state = E::FIN_WAIT1;
		iter->ap_cont.syscallUUID = syscallUUID;
		return;
	}
	else if(iter->tcp_state == E::CLOSE_WAIT)
	{
		//fprintf(stderr,"syscall_close: CLOSE_WAIT\n");
		uint8_t tmp;
		uint16_t checksum=0;
		uint8_t tcp_hd[20];
		int seq_num;
		Packet* FIN_pkt = this->allocatePacket(54);
		FIN_pkt->writeData(14+12, &(iter->src_addr), 4);
		FIN_pkt->writeData(14+16, &(iter->dest_addr), 4);
		FIN_pkt->writeData(14+20, &(iter->src_port), 2);
		FIN_pkt->writeData(14+20+2, &(iter->dest_port), 2);
		seq_num = htonl(this->seq_num);
		FIN_pkt->writeData(14+20+4, &seq_num,4);
		tmp = 0x50;
		FIN_pkt->writeData(14+20+12, &tmp, 1);
		tmp = 0x1;
		FIN_pkt->writeData(14+20+13, &tmp, 1);
		FIN_pkt->readData(14+20,tcp_hd,20);
		checksum = this->tcp_check_sum(iter->src_addr,iter->dest_addr, tcp_hd, 20);
		checksum = htons(checksum);
		FIN_pkt->writeData(14+20+16, &checksum, 2);
		this->sendPacket("IPv4",FIN_pkt);
		iter->seq_num = this->seq_num++;
		iter->tcp_state = E::LAST_ACK;
		iter->ap_cont.syscallUUID = syscallUUID;
		return;
	}
	//fprintf(stderr,"CLOSE: fd: %d, pid, %d\n", param1_int,pid);
	this->remove_tcplist(param1_int,pid);
	this->removeFileDescriptor(pid,param1_int);
	this->returnSystemCall(syscallUUID,0);
}

/* Bind a socket. If overlapped, return 1 else 0. */
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int param1_int, struct sockaddr* param2_ptr, socklen_t param3_int)
{
	if (this->check_overlap(param1_int, param2_ptr, pid))
		this->returnSystemCall(syscallUUID,1);
	else 
		this->returnSystemCall(syscallUUID,0);
}

/* Check overlapping. It returns true when there is no overlapping, 
   else add to tcp_list and return false. */
bool TCPAssignment::check_overlap(int fd, sockaddr* addr, int pid)
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
		if(((*cursor).pid == pid) && ((*cursor).socket_fd == check_fd))
			return true;

		/* Bind rule */
		if(( ((*cursor).src_addr == check_addr) || ((*cursor).src_addr == INADDR_ANY) || check_addr == INADDR_ANY )  && ((*cursor).src_port == check_port))
			return true;	
	}
	this->add_tcplist(check_fd, check_addr, check_port, pid);
	return false;
}

/* Get a socket name */
void TCPAssignment::syscall_getsockname(UUID syscallUUID,int pid,int param1_int, struct sockaddr* param2_ptr, socklen_t* param3_ptr)
{
	std::list<struct tcp_context>::iterator sock;
	
	/* Find socket */
	sock = this->find_tcplist(param1_int, pid);
	
	/* The socket_fd (param1_int) does not exist in tcp_list */
	if (sock == this->tcp_list.end())
		this->returnSystemCall(syscallUUID, 1);
	((struct sockaddr_in *) param2_ptr)->sin_family = AF_INET;
	((struct sockaddr_in *) param2_ptr)->sin_addr.s_addr = (*sock).src_addr;
	((struct sockaddr_in *) param2_ptr)->sin_port = (*sock).src_port;;
	
	this->returnSystemCall(syscallUUID, 0);
}


// Get a socket name
void TCPAssignment::syscall_getpeername(UUID syscallUUID,int pid,int param1_int, struct sockaddr* param2_ptr, socklen_t* param3_ptr)
{
	std::list<struct tcp_context>::iterator sock;

	// Find socket
	sock = this->find_tcplist(param1_int, pid);

	// The socket_fd (param1_int) does not exist in tcp_list
	if (sock == this->tcp_list.end())
		this->returnSystemCall(syscallUUID, 1);

	((struct sockaddr_in *) param2_ptr)->sin_family = AF_INET;
	((struct sockaddr_in *) param2_ptr)->sin_addr.s_addr = (*sock).dest_addr;
	((struct sockaddr_in *) param2_ptr)->sin_port = (*sock).dest_port;;

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int client_socket, struct sockaddr* connecting_addr, socklen_t len)
{
	//fprintf(stderr,"syscall_connect:start\n");
	uint32_t src_addr = 0xb000000;
	struct sockaddr_in addr;
	int seq_num;
	uint8_t tmp;
	uint16_t checksum=0;
	uint8_t tcp_hd[20];
	struct sockaddr_in* dest_addr = (sockaddr_in *)connecting_addr;
	std::list< struct tcp_context >::iterator iter = this->find_tcplist(client_socket, pid);
	if(iter == this->tcp_list.end())
	{
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = src_addr++;
		addr.sin_port = htons(this->port++);
		//fprintf(stderr,"syscall_connect:No socket exist\n");
		while(this->check_overlap(client_socket, (struct sockaddr *)&addr,pid))
		{
			//fprintf(stderr,"syscall_connect:error:overlapfailed\n");
			return;
		}
		iter = this->find_tcplist(client_socket, pid);
	}
	Packet* conn_SYN_pkt = this->allocatePacket(54);


	conn_SYN_pkt->writeData(14+12, &(iter->src_addr), 4);
	conn_SYN_pkt->writeData(14+16, &(dest_addr->sin_addr.s_addr), 4);
	conn_SYN_pkt->writeData(14+20, &(iter->src_port), 2);
	conn_SYN_pkt->writeData(14+20+2, &(dest_addr->sin_port), 2);
	seq_num = htonl(this->seq_num);
	conn_SYN_pkt->writeData(14+20+4, &seq_num,4);
	tmp = 0x50;
	conn_SYN_pkt->writeData(14+20+12, &tmp, 1);
	tmp = 0x2;
	conn_SYN_pkt->writeData(14+20+13, &tmp, 1);
	conn_SYN_pkt->readData(14+20,tcp_hd,20);
	checksum = this->tcp_check_sum(iter->src_addr,dest_addr->sin_addr.s_addr, tcp_hd, 20);
	checksum = htons(checksum);
	conn_SYN_pkt->writeData(14+20+16, &checksum, 2);
	this->sendPacket("IPv4",conn_SYN_pkt);
	iter->dest_addr = dest_addr->sin_addr.s_addr;
	iter->dest_port = dest_addr->sin_port;
	iter->tcp_state = E::SYN_SENT;
	iter->seq_num = this->seq_num++;
	iter->ap_cont.syscallUUID = syscallUUID;
	iter->ap_cont.client_addr = connecting_addr;
}

/* Listen param1 = sockfd, param2 = backlog */
void TCPAssignment::syscall_listen(UUID syscallUUID,int pid,int fd,int backlog)
{
	//fprintf(stderr,"syscall_listen\n");
	std::list<struct tcp_context>::iterator sock;
	sock = this->find_tcplist(fd, pid);
	if(!((*sock).is_bound))
		this->returnSystemCall(syscallUUID,1);
	(*sock).tcp_state = E::LISTEN;
	(*sock).backlog = backlog;
	this->returnSystemCall(syscallUUID,0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int param1_int,struct sockaddr* param2_ptr, socklen_t* param3_ptr)
{
	//fprintf(stderr,"syscall_accept:start>>pid: %d fd: %d\n", pid, param1_int);
	std::list< struct tcp_context >::iterator iter = find_tcplist(param1_int, pid);
	if(iter == this->tcp_list.end())
		this->returnSystemCall(syscallUUID, 1);
	//block the accept call if estb list is empty
	if((*iter).estb_conn_list.empty())
	{
		//fprintf(stderr,"syscall_accept:blocked>>pid: %d fd: %d\n", pid, param1_int);
		//save the accept param
		(*iter).ap_cont.syscallUUID = syscallUUID;
		(*iter).pid = pid;
		(*iter).socket_fd = param1_int;
		(*iter).ap_cont.client_addr = param2_ptr;
		(*iter).ap_cont.client_len = param3_ptr;
		(*iter).accept_cnt++;
		return;
	}
	else
	{
		//fprintf(stderr,"syscall_accept:continue>>pid: %d fd: %d\n", pid, param1_int);
		//pop the established connection and make a new file descriptor
		struct tcp_context estb_conn;
		int socket_fd;
		estb_conn = (*iter).estb_conn_list.front();
		(*iter).estb_conn_list.pop_front();
		socket_fd=this->createFileDescriptor(pid);
		estb_conn.socket_fd = socket_fd;
		estb_conn.pid = pid;
		((struct sockaddr_in *) param2_ptr)->sin_family = AF_INET;
		((struct sockaddr_in *) param2_ptr)->sin_addr.s_addr = estb_conn.src_addr;
		((struct sockaddr_in *) param2_ptr)->sin_port = estb_conn.src_port;
		estb_conn.tcp_state = E::ESTABLISHED;
		this->tcp_list.push_back(estb_conn);
		this->returnSystemCall(syscallUUID,socket_fd);
	}
}

//push packet data into read buffer
bool TCPAssignment::push_read_buffer(struct read_block *read_context, Packet *packet, int SEQ_NUM, size_t size)
{
    struct buf_block new_buf_block;
    if(read_context->find_read_buffer(SEQ_NUM) == read_context->read_buffer.end() && read_context->my_cwnd > read_context->read_buffer_size())
    {
        new_buf_block.packet = packet;
        new_buf_block.seq_num = SEQ_NUM;
        new_buf_block.ack_num = SEQ_NUM + (int)size;
        new_buf_block.data_size = size;
        read_context->read_buffer.push_back(new_buf_block);
        return true;
    }
    else
        return false;
}

//write all data from read_buffer to buffer
void TCPAssignment::pop_all_read_buffer(struct read_block *read_context)
{
    std::list<struct buf_block>::iterator iter = read_context->read_buffer.begin();
    while(!read_context->is_empty_read_buffer)
    {
        iter->packet->readData(54, read_context->cursor, iter->data_size);
        read_context->cursor += iter->data_size;
        this->freePacket(iter->packet);
        iter = read_context->read_buffer.erase(iter);
    }
}

//check if cwnd is full or left data is all recieved. If it is, write data to the buffer.
void TCPAssignment::read_from_packet(struct read_block *read_context)
{
    if(read_context->left_size <= read_context->read_buffer_size() * MSS)
    {
        pop_all_read_buffer(read_context);
        read_context->my_cwnd = 1;
        read_context->read_flag = false;
        read_context->max_ack_num = 0;
        this->returnSystemCall(read_context->syscall_UUID, size_t(read_context->cursor - read_context->buffer));
    }
    else if(read_context->read_buffer_size() == read_context->my_cwnd)
    {
        pop_all_read_buffer(read_context);
        read_context->my_cwnd *= 2;
    }  
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int socket_fd, void *buffer, size_t size)
{
    
}

//pop_acked_write_buffer: pop the buffer until acked one
bool TCPAssignment::pop_acked_write_buffer(struct write_block *write_context, unsigned int ACK_NUM)
{
	//ignore if smaller than already acked num
	if(ACK_NUM <= write_context->max_ack_num){
		return false;
	}
	std::list<struct buf_block>::iterator iter = write_context->get_ack_write_buffer(ACK_NUM);
	if(iter == write_context->write_buffer.end()){
		return false;
	}
	else{
		for(iter = write_context->write_buffer.begin();iter != write_context->write_buffer.end();iter++){
			if(iter->ack_num == ACK_NUM){
				this->freePacket(iter->packet);
				break;
			}
			this->freePacket(iter->packet);
		}
		write_context->write_buffer.erase(write_context->write_buffer.begin(),++iter);
		write_context->buf_len = write_context->write_buffer.size();
		write_context->max_ack_num = ACK_NUM;
		return true;
	}
}

Packet *TCPAssignment::make_packet(std::list<struct tcp_context>::iterator iter, size_t payload_size)
{
	uint8_t tmp;
	uint16_t checksum=0;
	uint8_t tcp_hd[20];
	int seq_num;
	Packet* new_pkt = this->allocatePacket(54 + payload_size);
	//Make header first
	new_pkt->writeData(14+12, &(iter->src_addr), 4);
	new_pkt->writeData(14+16, &(iter->dest_addr), 4);
	new_pkt->writeData(14+20, &(iter->src_port), 2);
	new_pkt->writeData(14+20+2, &(iter->dest_port), 2);
	seq_num = htonl(this->seq_num);
	new_pkt->writeData(14+20+4, &seq_num,4);
	tmp = 0x50;
	new_pkt->writeData(14+20+12, &tmp, 1);
	tmp = 0x0;
	new_pkt->writeData(14+20+13, &tmp, 1);
	new_pkt->readData(14+20,tcp_hd,20);
	checksum = this->tcp_check_sum(iter->src_addr,iter->dest_addr, tcp_hd, 20);
	checksum = htons(checksum);
	new_pkt->writeData(14+20+16, &checksum, 2);

	//write data into packet
	new_pkt->writeData(54, iter->write_context.cursor, payload_size);
	return new_pkt;
}

void TCPAssignment::write_to_packet(int pid, int sock_fd)
{
	std::list<struct tcp_context>::iterator iter;
	struct write_block *write_context;
	Packet* new_packet;
	Packet* send_packet;
	iter = find_tcplist(sock_fd, pid);
	if(iter == this->tcp_list.end())
		fprintf(stderr,"WRITE: Cannot find TCP_CONTEXT\n");
	write_context = &(iter->write_context);
	while(write_context->is_full_write_buffer()){
		if(write_context->current_size < MSS){
			//should fill in
			new_packet = make_packet(iter, write_context->current_size);
			write_context->push_write_buffer(&(this->seq_num), new_packet, write_context->current_size);
			send_packet = this->clonePacket(new_packet);
			this->sendPacket("IPv4",send_packet);
			write_context->current_size -= write_context->current_size;
			write_context->cursor += write_context->current_size;
			break;
		}
		new_packet = make_packet(iter,MSS);
		write_context->push_write_buffer(&(this->seq_num),new_packet,MSS);
		send_packet = this->clonePacket(new_packet);
		this->sendPacket("IPv4",send_packet);
		write_context->current_size -= MSS;
		write_context->cursor += (size_t)MSS;
	}
}

/* Return buffer size */
void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sock_fd, void * buffer, size_t size)
{
    /* Save param to write_block */
    std::list<struct tcp_context>::iterator iter;
    iter = find_tcplist(sock_fd, pid);
    if(iter == this->tcp_list.end())
        fprintf(stderr,"WRITE: Cannot find TCP_CONTEXT\n");
    iter->write_context.syscall_UUID = syscallUUID;
    iter->write_context.buffer = (uint8_t *)buffer;
    iter->write_context.current_size = size;
    iter->write_context.cursor = (uint8_t *)buffer;

    /* WRITE PART */
    write_to_packet(pid,sock_fd);
    return;
}



/* Add new socket block to tcp_list
   Copy socket_fd, addr and port from args to new 'tcp_context sock' */
void TCPAssignment::add_tcplist(int fd, uint32_t addr, unsigned short int port, int pid)
{
	tcp_context sock;
	sock.pid = pid;
	sock.socket_fd = fd;
	sock.src_addr = addr;
	sock.src_port = port;
	sock.is_bound = true;
	
	this->tcp_list.push_back(sock);
}

/* Remove socket from tcp_list */
void TCPAssignment::remove_tcplist(int fd, int pid)
{
	std::list<struct tcp_context>::iterator cursor;
	
	cursor=this->tcp_list.begin();
	//fprintf(stderr,"remmove tcplist start\n");
	while(cursor != this->tcp_list.end()){
		if ((*cursor).socket_fd == fd && (*cursor).pid ==pid)
		{
			cursor=this->tcp_list.erase(cursor);
			//fprintf(stderr,"remove tcplist complete\n");
		}
		else
			++cursor;
	}
	//fprintf(stderr,"remove tcplist end\n");
}

/* Find a socket. If it does not exist in list, return list.end(). */
std::list<struct tcp_context>::iterator  TCPAssignment::find_tcplist(int fd, int pid)
{
	//fprintf(stderr,"find_tcplist:\nfinding fd: %d pid: %d\n",fd,pid);
	std::list<struct tcp_context>::iterator cursor;
	
	for(cursor=this->tcp_list.begin(); cursor != this->tcp_list.end(); ++cursor){
		//fprintf(stderr,"current_tcplist:\nfinding fd: %d pid: %d\n",cursor->socket_fd,cursor->pid);
		if((*cursor).socket_fd == fd && (*cursor).pid == pid)
			return cursor;
	}
	return this->tcp_list.end();
}

/* Find a socket. If it does not exist in list, return list.end(). */
std::list<struct tcp_context>::iterator TCPAssignment::find_listen(uint32_t addr, uint16_t port)
{
	std::list< struct tcp_context >::iterator cursor;

	for(cursor=this->tcp_list.begin(); cursor != this->tcp_list.end(); ++cursor){
		if(((*cursor).tcp_state == E::LISTEN) && ( (*cursor).src_addr == addr || (*cursor).src_addr == 0) && ((*cursor).src_port == port) )
			return cursor;
	}
	return this->tcp_list.end();
}

/* Find a socket. If it does not exist in list, return list.end(). */
std::list<struct tcp_context>::iterator TCPAssignment::find_client(uint32_t addr, uint16_t port)
{
	std::list< struct tcp_context >::iterator cursor;
	//fprintf(stderr,"find_client:addr: %x, port: %u\n",addr,port);
	for(cursor=this->tcp_list.begin(); cursor != this->tcp_list.end(); ++cursor){
		if(((*cursor).tcp_state == E::SYN_SENT) && ( (*cursor).src_addr == addr || (*cursor).src_addr == 0) && ((*cursor).src_port == port) )
			return cursor;
	}
	return this->tcp_list.end();
}

/* Find a socket. If it does not exist in list, return list.end(). */
std::list<struct tcp_context>::iterator TCPAssignment::get_tcp_state(uint32_t src_addr, uint16_t src_port, uint32_t dest_addr, uint16_t dest_port)
{
	std::list< struct tcp_context >::iterator cursor;
	//fprintf(stderr,"find_client:addr: %x, port: %u\n",addr,port);
	for(cursor=this->tcp_list.begin(); cursor != this->tcp_list.end(); ++cursor){
		if(((*cursor).src_addr == src_addr || (*cursor).src_addr == 0) && ((*cursor).src_port == src_port) && (*cursor).dest_addr == dest_addr && ((*cursor).dest_port == dest_port) && (*cursor).tcp_state != E::SYN_SENT)
			return cursor;
	}
	return this->tcp_list.end();
}

//find connection having seq_num in the pending list
std::list< struct tcp_context >::iterator TCPAssignment::find_conn(int seq_num, std::list< struct tcp_context > *pend_conn_list_ptr)
{
	std::list< struct tcp_context >::iterator cursor;
	for(cursor=(*pend_conn_list_ptr).begin(); cursor != (*pend_conn_list_ptr).end(); ++cursor){
		if((*cursor).seq_num == seq_num)
			return cursor;
	}
	return (*pend_conn_list_ptr).end();
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
	//fprintf(stderr,"------------packetArrived-------------\n");
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
	bool SYN, ACK, FIN;
	int tmp_num;
	int socket_case = E::LISTEN;
	std::list<struct tcp_context>::iterator listen_socket;
	std::list<struct tcp_context>::iterator conn_socket;
	std::list<struct tcp_context>::iterator closing_socket;
	std::list< struct tcp_context > *pending_conn_list_ptr;
	std::list< struct tcp_context > *estb_conn_list_ptr;
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
	FIN = bool(tmp[0] & 0x1);
	SYN = bool(tmp[0] & 0x2);
	ACK = bool(tmp[0] & 0x10);

	//check if the corresponding socket(non-listen socket first)
	closing_socket = get_tcp_state(*(uint32_t *)dest_ip, *(uint16_t *)dest_port,*(uint32_t *)src_ip, *(uint16_t *)src_port);
	if(closing_socket == tcp_list.end())
	{
		listen_socket = find_listen(*(uint32_t *)dest_ip, *(uint16_t *)dest_port);
		if(listen_socket == tcp_list.end())
		{
			conn_socket = find_client(*(uint32_t *)dest_ip, *(uint16_t *)dest_port);
			if(conn_socket == tcp_list.end())
				socket_case = E::CLOSED;
			else
				socket_case = E::SYN_SENT;
		}
	}
	else
		socket_case = closing_socket->tcp_state;


	if(FIN)
	{
		//fprintf(stderr,"FIN %d\n", socket_case);
	}

	switch(socket_case)
	{
	case E::LISTEN:
	{
		//allocate listen_socket's pending list
		pending_conn_list_ptr = &((*listen_socket).pending_conn_list);
		estb_conn_list_ptr = &((*listen_socket).estb_conn_list);

		if(SYN)//SYN
		{
			//fprintf(stderr,"----------------SERVER SYN handler-----------\n%x %d\n",*(uint32_t *)dest_ip, *(uint16_t *)dest_port);
			//check pending list size doesn't exceed backlog value
			if(pending_conn_list_ptr->size() >= (*listen_socket).backlog)
			{
				this->freePacket(packet);
				return;
			}

			//build new connection
			struct tcp_context new_conn;
			int seq_tmp;
			new_conn.dest_addr = *(uint32_t *)src_ip;
			new_conn.dest_port = *(uint16_t *) src_port;
			new_conn.src_addr = *(uint32_t *) dest_ip;
			new_conn.src_port = *(uint16_t *) dest_port;
			seq_tmp = htonl(this->seq_num);
			new_conn.seq_num = this->seq_num++;
			new_conn.tcp_state = E::SYN_RCVD;
			//push in to pending connection list
			(*pending_conn_list_ptr).push_back(new_conn);


			tmp_num = ntohl(*(int *)seq_num) + 1;
			tmp_num = htonl(tmp_num);
			//Send ACK message
			Packet* SYN_pkt = this->clonePacket(packet);
			SYN_pkt->writeData(14+12, dest_ip, 4);
			SYN_pkt->writeData(14+16, src_ip, 4);
			SYN_pkt->writeData(14+IHL[0]*4, dest_port, 2);
			SYN_pkt->writeData(14+IHL[0]*4+2, src_port, 2);
			SYN_pkt->writeData(14+IHL[0]*4+4, &seq_tmp,4);
			SYN_pkt->writeData(14+IHL[0]*4+8, &tmp_num,4);
			SYN_pkt->writeData(14+IHL[0]*4+16, &checksum, 2);
			tmp[0] = 0x12;
			SYN_pkt->writeData(14+IHL[0]*4+13, tmp,1);
			SYN_pkt->readData(14+IHL[0]*4,tcp_hd,20);
			checksum = this->tcp_check_sum(*(uint32_t *)src_ip,*(uint32_t *)dest_ip, tcp_hd, 20);
			checksum = htons(checksum);
			SYN_pkt->writeData(14+IHL[0]*4+16, &checksum, 2);

			this->sendPacket("IPv4", SYN_pkt);
		}
		if(ACK)//ACK
		{
			//fprintf(stderr,"----------------SERVER ACK handler-----------\n%x %d\n",*(uint32_t *)dest_ip, *(uint16_t *)dest_port);
			//fprintf(stderr,"listen socket:ACK handler>>pid: %d fd: %d\n", listen_socket->pid, listen_socket->socket_fd);
			std::list<struct tcp_context>::iterator iter;
			struct tcp_context estb_conn;
			//find following connection
			iter = this->find_conn(int(ntohl(*(uint32_t *)ack_num))-1, pending_conn_list_ptr);
			if(iter == (*pending_conn_list_ptr).end())
			{
				this->freePacket(packet);
				return;
			}
			estb_conn = *iter;
			//move the connection from pending list to estb list
			(*pending_conn_list_ptr).erase(iter);
			estb_conn.tcp_state = E::ESTABLISHED;
			(*estb_conn_list_ptr).push_back(estb_conn);
			if((*listen_socket).accept_cnt != 0)
			{
				//fprintf(stderr,"listen socket:ACK handler:unblock accept>>pid: %d fd: %d\n", listen_socket->pid, listen_socket->socket_fd);
				(*listen_socket).accept_cnt--;
				//pop the established connection and make a new file descriptor
				struct tcp_context finished_conn;
				int socket_fd;
				finished_conn = (*estb_conn_list_ptr).front();
				(*estb_conn_list_ptr).pop_front();
				socket_fd = this->createFileDescriptor(listen_socket->pid);
				finished_conn.socket_fd = socket_fd;
				finished_conn.pid = (*listen_socket).pid;
				((struct sockaddr_in *) (*listen_socket).ap_cont.client_addr)->sin_family = AF_INET;
				((struct sockaddr_in *) (*listen_socket).ap_cont.client_addr)->sin_addr.s_addr = finished_conn.src_addr;
				((struct sockaddr_in *) (*listen_socket).ap_cont.client_addr)->sin_port = finished_conn.src_port;
				finished_conn.tcp_state = E::ESTABLISHED;
				this->tcp_list.push_back(finished_conn);
				this->returnSystemCall((*listen_socket).ap_cont.syscallUUID,socket_fd);
			}
		}
	}
		break;
	case E::SYN_SENT:
	{
		//allocate listen_socket's pending list
		pending_conn_list_ptr = &((*conn_socket).pending_conn_list);
		estb_conn_list_ptr = &((*conn_socket).estb_conn_list);

		if(SYN)//SYN
		{
			//fprintf(stderr,"----------------CLIENT SYN handler-----------\n%x %d\n",*(uint32_t *)dest_ip, *(uint16_t *)dest_port);

			tmp_num = ntohl(*(int *)seq_num) + 1;
			tmp_num = htonl(tmp_num);
			//Send ACK message
			Packet* SYN_pkt = this->clonePacket(packet);
			SYN_pkt->writeData(14+12, dest_ip, 4);
			SYN_pkt->writeData(14+16, src_ip, 4);
			SYN_pkt->writeData(14+IHL[0]*4, dest_port, 2);
			SYN_pkt->writeData(14+IHL[0]*4+2, src_port, 2);
			SYN_pkt->writeData(14+IHL[0]*4+8, &tmp_num,4);
			SYN_pkt->writeData(14+IHL[0]*4+16, &checksum, 2);
			tmp[0] = 0x10;
			SYN_pkt->writeData(14+IHL[0]*4+13, tmp,1);
			SYN_pkt->readData(14+IHL[0]*4,tcp_hd,20);
			checksum = this->tcp_check_sum(*(uint32_t *)src_ip,*(uint32_t *)dest_ip, tcp_hd, 20);
			checksum = htons(checksum);
			SYN_pkt->writeData(14+IHL[0]*4+16, &checksum, 2);
			this->sendPacket("IPv4", SYN_pkt);
		}
		if(ACK)
		{
			if(ntohl(*(uint32_t *)ack_num)-1 == (unsigned int)conn_socket->seq_num)
			{
				conn_socket->tcp_state = E::ESTABLISHED;
				this->returnSystemCall(conn_socket->ap_cont.syscallUUID,0);
			}
			else
				this->returnSystemCall(conn_socket->ap_cont.syscallUUID,1);
		}
	}
		break;
	case E::ESTABLISHED:
	{
		//fprintf(stderr,"ESTABLISHED: start\n");
		if(FIN)
		{
			//Send ACK message
			Packet* ACK_pkt = this->clonePacket(packet);
			ACK_pkt->writeData(14+12, dest_ip, 4);
			ACK_pkt->writeData(14+16, src_ip, 4);
			ACK_pkt->writeData(14+IHL[0]*4, dest_port, 2);
			ACK_pkt->writeData(14+IHL[0]*4+2, src_port, 2);
			tmp_num = 0;
			ACK_pkt->writeData(14+IHL[0]*4+4, &tmp_num,4);
			tmp_num = ntohl(*(int *)seq_num) + 1;
			tmp_num = htonl(tmp_num);
			ACK_pkt->writeData(14+IHL[0]*4+8, &tmp_num,4);
			ACK_pkt->writeData(14+IHL[0]*4+16, &checksum, 2);
			tmp[0] = 0x10;
			ACK_pkt->writeData(14+IHL[0]*4+13, tmp,1);
			ACK_pkt->readData(14+IHL[0]*4,tcp_hd,20);
			checksum = this->tcp_check_sum(*(uint32_t *)src_ip,*(uint32_t *)dest_ip, tcp_hd, 20);
			checksum = htons(checksum);
			ACK_pkt->writeData(14+IHL[0]*4+16, &checksum, 2);
			this->sendPacket("IPv4", ACK_pkt);
			closing_socket->tcp_state = E::CLOSE_WAIT;
			//fprintf(stderr,"ESTABLISHED: ACK_packet Sent\nack_num: %d\n", ntohl(*(unsigned int *)seq_num) + 1);
		}
		if(ACK)
		{
			//need to fill in
			if(pop_acked_write_buffer(&(closing_socket->write_context), ntohl(*(int *)ack_num)))
			{
				if(closing_socket->write_context.current_size == 0 && closing_socket->write_context.write_buffer.empty())
					this->returnSystemCall(closing_socket->write_context.syscall_UUID, size_t(closing_socket->write_context.cursor - closing_socket->write_context.buffer));
				write_to_packet(closing_socket->pid,closing_socket->socket_fd);
			}
		}
	}
		break;
	case E::CLOSE_WAIT:
	{
		if(ACK)
		{
			//need to fill in
			if(pop_acked_write_buffer(&(closing_socket->write_context), ntohl(*(int *)ack_num)))
			{
				if(closing_socket->write_context.current_size == 0 && closing_socket->write_context.write_buffer.empty())
					this->returnSystemCall(closing_socket->write_context.syscall_UUID, size_t(closing_socket->write_context.cursor - closing_socket->write_context.buffer));
				write_to_packet(closing_socket->pid,closing_socket->socket_fd);
			}
		}
	}
		break;
	case E::FIN_WAIT1:
	{
		//fprintf(stderr,"FIN_WAIT1\n");
		if(FIN)
		{
			closing_socket->fin_num = ntohl(*(uint32_t *)seq_num);
			closing_socket->tcp_state = E::FIN_WAIT2;
			closing_socket->fin_ready = true;
		}
		else if(ACK)
		{
			if((uint32_t)closing_socket->seq_num == ntohl(*(uint32_t *)ack_num)-1)
			{
				closing_socket->tcp_state = E::FIN_WAIT2;
				closing_socket->ack_ready = true;
			}
		}
	}
		break;
	case E::FIN_WAIT2:
	{
		//fprintf(stderr,"FIN_WAIT2\n");
		if(FIN && closing_socket->ack_ready)
		{
			closing_socket->fin_num = ntohl(*(uint32_t *)seq_num);
			closing_socket->tcp_state = E::TIME_WAIT;
			closing_socket->fin_ready = true;
		}
		else if(ACK && closing_socket->fin_ready)
		{
			if((uint32_t)closing_socket->seq_num == ntohl(*(uint32_t *)ack_num)-1)
			{
				closing_socket->tcp_state = E::TIME_WAIT;
				closing_socket->ack_ready = true;
			}
			else
				break;
		}
		if(closing_socket->fin_ready && closing_socket->ack_ready)
		{
			tmp_num = closing_socket->fin_num + 1;
			tmp_num = htonl(tmp_num);
			//Send ACK message
			Packet* ACK_pkt = this->clonePacket(packet);
			ACK_pkt->writeData(14+12, dest_ip, 4);
			ACK_pkt->writeData(14+16, src_ip, 4);
			ACK_pkt->writeData(14+IHL[0]*4, dest_port, 2);
			ACK_pkt->writeData(14+IHL[0]*4+2, src_port, 2);
			ACK_pkt->writeData(14+IHL[0]*4+8, &tmp_num,4);
			ACK_pkt->writeData(14+IHL[0]*4+16, &checksum, 2);
			tmp[0] = 0x10;
			ACK_pkt->writeData(14+IHL[0]*4+13, tmp,1);
			ACK_pkt->readData(14+IHL[0]*4,tcp_hd,20);
			checksum = this->tcp_check_sum(*(uint32_t *)src_ip,*(uint32_t *)dest_ip, tcp_hd, 20);
			checksum = htons(checksum);
			ACK_pkt->writeData(14+IHL[0]*4+16, &checksum, 2);
			this->sendPacket("IPv4", ACK_pkt);

			uint8_t ttl;
			packet->readData(14+8,&ttl,1);
			struct timer_idx *new_tidx = (struct timer_idx *)malloc(sizeof(struct timer_idx));
			new_tidx->pid = closing_socket->pid;
			new_tidx->fd = closing_socket->socket_fd;
			this->addTimer(new_tidx, this->getHost()->getSystem()->getCurrentTime() + 2*ttl*1000);
			this->removeFileDescriptor(closing_socket->socket_fd,closing_socket->pid);
		}
		//fprintf(stderr,"FIN_WAIT2 END\n");
	}
		break;
	case E::LAST_ACK:
	{
		//fprintf(stderr,"LAST_ACK\n");
		if(ACK)
		{
			if((uint32_t)closing_socket->seq_num == ntohl(*(uint32_t *)ack_num)-1)
			{
				closing_socket->tcp_state = E::CLOSED;
				this->remove_tcplist(closing_socket->socket_fd, closing_socket->pid);
				this->removeFileDescriptor(closing_socket->socket_fd,closing_socket->pid);
				this->returnSystemCall(closing_socket->ap_cont.syscallUUID,0);
			}
		}
	}
		break;
	case E::TIME_WAIT:
	{
		//fprintf(stderr,"TIME_WAIT\n");
		if(FIN)
		{
			closing_socket->fin_num = ntohl(*(uint32_t *)seq_num);
			tmp_num = ntohl(closing_socket->fin_num) + 1;
			tmp_num = htonl(tmp_num);
			//Send ACK message
			Packet* ACK_pkt = this->clonePacket(packet);
			ACK_pkt->writeData(14+12, dest_ip, 4);
			ACK_pkt->writeData(14+16, src_ip, 4);
			ACK_pkt->writeData(14+IHL[0]*4, dest_port, 2);
			ACK_pkt->writeData(14+IHL[0]*4+2, src_port, 2);
			ACK_pkt->writeData(14+IHL[0]*4+8, &tmp_num,4);
			ACK_pkt->writeData(14+IHL[0]*4+16, &checksum, 2);
			tmp[0] = 0x10;
			ACK_pkt->writeData(14+IHL[0]*4+13, tmp,1);
			ACK_pkt->readData(14+IHL[0]*4,tcp_hd,20);
			checksum = this->tcp_check_sum(*(uint32_t *)src_ip,*(uint32_t *)dest_ip, tcp_hd, 20);
			checksum = htons(checksum);
			ACK_pkt->writeData(14+IHL[0]*4+16, &checksum, 2);
			this->sendPacket("IPv4", ACK_pkt);
		}
	}
		break;
	case E::CLOSED:
		break;
	}
	//given packet is my responsibility
	this->freePacket(packet);
}

void TCPAssignment::timerCallback(void* payload)
{
	//fprintf(stderr,"CB\n");
	std::list< struct tcp_context >::iterator iter = this->find_tcplist(((struct timer_idx *)payload)->fd,((struct timer_idx *)payload)->pid);
	if(iter==this->tcp_list.end())
	{
		//fprintf(stderr,"CB:empty, pid: %d, fd: %d\n",((struct timer_idx *)payload)->pid,((struct timer_idx *)payload)->fd);
	}
	iter->tcp_state = E::CLOSED;
	UUID uuid = iter->ap_cont.syscallUUID;
	this->remove_tcplist(iter->socket_fd, iter->pid);
	free((struct timer_idx *)payload);
	//fprintf(stderr,"CB END\n");
	this->returnSystemCall(uuid,0);
}


}
