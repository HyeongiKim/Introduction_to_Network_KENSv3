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
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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
	this->remove_socketlist(param1_int);
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
   else add to socket_list and return false. */
bool TCPAssignment::check_overlap(int fd, sockaddr* addr)
{
	int check_fd;
	uint32_t check_addr;
	unsigned short int check_port;
	std::list<struct socket_block>::iterator cursor;
	
	struct sockaddr_in* check_sock = (sockaddr_in *)addr;
	check_fd = fd;
	check_addr = check_sock->sin_addr.s_addr;
	check_port = check_sock->sin_port;

	for(cursor=this->socket_list.begin(); cursor != this->socket_list.end(); ++cursor)
	{
		/* Already socket_fd exists in socket_list */
		if((*cursor).socket_fd == check_fd)
			return true;

		/* Bind rule */
		if(( ((*cursor).addr == check_addr) || ((*cursor).addr == INADDR_ANY) || check_addr == INADDR_ANY )  && ((*cursor).port == check_port))
			return true;	
	}
	this->add_socketlist(check_fd, check_addr, check_port);
	return false;
}

/* Get a socket name */
void TCPAssignment::syscall_getsockname(UUID syscallUUID,int pid,int param1_int, struct sockaddr* param2_ptr, socklen_t* param3_ptr)
{
	std::list<struct socket_block>::iterator sock;
	
	/* Find socket */
	sock = this->find_socketlist(param1_int);
	
	/* The socket_fd (param1_int) does not exist in socket_list */
	if (sock == this->socket_list.end())
		this->returnSystemCall(syscallUUID, 1);
	
	((struct sockaddr_in *) param2_ptr)->sin_family = AF_INET;
	((struct sockaddr_in *) param2_ptr)->sin_addr.s_addr = (*sock).addr;
	((struct sockaddr_in *) param2_ptr)->sin_port = (*sock).port;;
	
	this->returnSystemCall(syscallUUID, 0);
}
/* Add new socket block to socket_list
   Copy socket_fd, addr and port from args to new 'socket_block sock' */
void TCPAssignment::add_socketlist(int fd, uint32_t addr, unsigned short int port)
{
	socket_block sock;
	sock.socket_fd = fd;
	sock.addr = addr;
	sock.port = port;

	this->socket_list.push_back(sock);
}

/* Remove socket from socket_list */
void TCPAssignment::remove_socketlist(int fd)
{
	std::list<struct socket_block>::iterator cursor;
	
	cursor=this->socket_list.begin();
	
	while(cursor != this->socket_list.end()){
		if ((*cursor).socket_fd == fd)
			this->socket_list.erase(cursor);
		++cursor;
	}
}

/* Find a socket. If it does not exist in list, return list.end(). */
std::list<struct socket_block>::iterator  TCPAssignment::find_socketlist(int fd)
{
	std::list<struct socket_block>::iterator cursor;
	
	for(cursor=this->socket_list.begin(); cursor != this->socket_list.end(); ++cursor){
		if((*cursor).socket_fd == fd)
			return cursor;
	}
	return this->socket_list.end();
}
void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	//Simple L3 forwarding
	//extract address
	uint8_t src_ip[4];
	uint8_t dest_ip[4]; 
	packet->readData(14+12, src_ip, 4); 
	packet->readData(14+16, dest_ip, 4);
	Packet* myPacket = this->clonePacket(packet); //prepare to send
	
	//swap src and dest
	myPacket->writeData(14+12, dest_ip, 4); 
	myPacket->writeData(14+16, src_ip, 4);
	
	//IP module will fill rest of IP header, 
	//send it to correct network interface 
	this->sendPacket("IPv4", myPacket);
	
	//given packet is my responsibility
	this->freePacket(packet);
}

void TCPAssignment::timerCallback(void* payload)
{

}


}
