/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 * 	  Modified: 김현기 20110032, 심영보 20110560
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <list> //Add by Hyeongi Kim

#include <E/E_TimerModule.hpp>

namespace E
{	
	/* TCP STATE */
	enum TCP_STATE {
		CLOSED,
		LISTEN,
		SYN_SENT,
		SYN_RCVD,
		ESTABLISHED,
		FIN_WAIT1,
		FIN_WAIT2,
		CLOSING,
		TIME_WAIT,
		LAST_ACK 
	};

	struct accept_param_container{
			UUID syscallUUID;
			//int pid;
			//int server_sock_fd;
			struct sockaddr* client_addr;
			socklen_t* client_len;
		};

	/* TCP CONTEXT */
	struct tcp_context {
		int pid;
		int socket_fd;
		uint32_t src_addr;
		unsigned short int src_port;
		uint32_t dest_addr;
		unsigned short int dest_port;
		bool is_bound = false;;
		TCP_STATE tcp_state = CLOSED;
		int seq_num;
		struct accept_param_container ap_cont;
		std::list< struct tcp_context > pending_conn_list;
		std::list< struct tcp_context > estb_conn_list;
		unsigned int backlog;
		unsigned int accept_cnt = 0;
	};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	/* list of socket_blocks */
	std::list< struct tcp_context > tcp_list;
	int seq_num = 0;
private:
	virtual void timerCallback(void* payload) final;
	/* Assignment */
	void syscall_socket(UUID syscallUUID, int pid, int param1_int, int param2_int);
	void syscall_close(UUID syscallUUID, int pid, int param1_int);
	void syscall_bind(UUID syscallUUID, int pid, int param1_int, struct sockaddr* param2_ptr, socklen_t param3_int);
	bool check_overlap(int fd, sockaddr* addr, int pid);
	void syscall_getsockname(UUID syscallUUID,int pid,int param1_int, struct sockaddr* param2_ptr, socklen_t* param3_ptr);
	void syscall_getpeername(UUID syscallUUID,int pid,int param1_int, struct sockaddr* param2_ptr, socklen_t* param3_ptr);
	void syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
	void syscall_accept(UUID syscallUUID, int pid, int param1_int,struct sockaddr* param2_ptr, socklen_t* param3_ptr);
	void add_tcplist(int fd, uint32_t addr, unsigned short int port, int pid);
	void remove_tcplist(int fd);
	std::list< struct tcp_context >::iterator find_tcplist(int fd);
	std::list<struct tcp_context>::iterator find_listen(uint32_t addr,uint16_t port);
	std::list< struct tcp_context >::iterator find_conn(int seq_num, std::list< struct tcp_context > *pend_conn_list_ptr);
	uint16_t one_sum(const uint8_t* buffer, size_t size);
	uint16_t tcp_check_sum(uint32_t source, uint32_t dest, const uint8_t* tcp_seg, size_t length);

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
