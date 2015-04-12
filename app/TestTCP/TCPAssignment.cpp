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
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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

/* Close a socket. If success, returns 0 else 1.*/
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int param1_int)
{
	this->removeFileDescriptor(pid,param1_int);
	this->returnSystemCall(syscallUUID,0);
}

/* Bind a socket. If overlapped, return 1 else 0. */
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int param1_int, sockaddr* param2_ptr, socklen_t param3_int)
{
	if (this->check_overlap(param1_int, param2_ptr))
		this->returnSystemCall(syscallUUID,1);
	else 
		this->returnSystemCall(syscallUUID,0);
}

/* Check overlapping. It returns true when there is no overlapping, 
   else add to socket_list and return false.
 * 		Address is consist of ip_address and port_number (sockaddr_in)
 * 		143.248.234.2:5555 and 10.0.0.2:5555 do not overlap
 * 		143.248.234.2:5555 and 0.0.0.0:5555 overlap (INADDR_ANY)
 * 		143.248.234.2:5555 and 143.248.234.3:5555 do not overlap
 * 		0.0.0.0:5555 and 0.0.0.0:5556 do not overlap (different port)
 * 		Closed sockets do not overlap with any socket */
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
		//bool addr_eq;
		//bool port_eq;
		/* Already socket_fd exists in socket_list */
		if((*cursor).socket_fd == check_fd)
			return true;
		/* Already same addr & port exist in socket_list */
		/*
		if((addr_eq = ((*cursor).addr == check_addr)) || (port_eq = ((*cursor).port == check_port))){
			if(addr_eq && port_eq)
				return true;
			else if (addr_eq && ((*cursor).addr != 0) && !port_eq) // Discard 0.0.0.0:5555 and 0.0.0.0:5556 case.
				return true;
			else if (port_eq && ( ((*cursor).addr == 0) || (check_addr == 0) )) //143.248.234.2:5555 and 0.0.0.0:5555 overlap (INADDR_ANY)
				return true;
		}
		*/
		if(( ((*cursor).addr == check_addr) || ((*cursor).addr == INADDR_ANY) || check_addr == INADDR_ANY )  && ((*cursor).port == check_port))
			return true;
		/*
		else if (addr_eq && !port_eq){ 
			if ((*cursor).addr != 0)// Discard 0.0.0.0:5555 and 0.0.0.0:5556 case.
				return true;
		}
		
		if (!addr_eq && port_eq){
			if ((*cursor).addr == 0 ) //143.248.234.2:5555 and 0.0.0.0:5555 overlap (INADDR_ANY)
				return true;
		}*/
		
	}
	this->add_socketlist(check_fd, check_addr, check_port);
	return false;
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
void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
