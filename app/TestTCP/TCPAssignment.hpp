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

	/* TCP CONTEXT */
	struct tcp_context {
		int socket_fd;
		uint32_t src_addr;
		unsigned short int src_port;
		uint32_t dest_addr;
		unsigned short int dest_port;
		bool is_bound = false;;
		TCP_STATE tcp_state = CLOSED;
		int seq_num;
		/*
		tcp_context& operator = (const tcp_context& t){
			this->dest_addr = t.dest_addr;
			this->dest_port = t.dest_port;
			this->is_bound = t.is_bound;
			this->seq_num = t.seq_num;
			this->socket_fd = t.socket_fd;
			this->src_addr = t.src_addr;
			this->src_port = t.src_port;
			this->tcp_state = t.tcp_state;
			return *this;
		}
		*/
	};

	struct accept_param_container{
		UUID syscallUUID;
		int pid;
		int server_sock_fd;
		struct sockaddr* client_addr;
		socklen_t* client_len;
	};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	/* list of socket_blocks */
	std::list< struct tcp_context > tcp_list;
	int seq_num = 0;
	unsigned int backlog;
	bool accept_flag = false;
	struct accept_param_container ap_cont;
	std::list< struct tcp_context > pending_conn_list;
	std::list< struct tcp_context > estb_conn_list;
private:
	virtual void timerCallback(void* payload) final;
	/* Assignment */
	void syscall_socket(UUID syscallUUID, int pid, int param1_int, int param2_int);
	void syscall_close(UUID syscallUUID, int pid, int param1_int);
	void syscall_bind(UUID syscallUUID, int pid, int param1_int, struct sockaddr* param2_ptr, socklen_t param3_int);
	bool check_overlap(int fd, sockaddr* addr);
	void syscall_getsockname(UUID syscallUUID,int pid,int param1_int, struct sockaddr* param2_ptr, socklen_t* param3_ptr);
	void syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
	void syscall_accept(UUID syscallUUID, int pid, int param1_int,struct sockaddr* param2_ptr, socklen_t* param3_ptr);
	void add_tcplist(int fd, uint32_t addr, unsigned short int port);
	void remove_tcplist(int fd);
	std::list< struct tcp_context >::iterator find_tcplist(int fd);
	int find_listen();
	std::list< struct tcp_context >::iterator* find_conn(int seq_num);
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
