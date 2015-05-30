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
#include <E/Networking/E_RoutingInfo.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <list> //Add by Hyeongi Kim

#include <E/E_TimerModule.hpp>

#define MSS 512

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
		CLOSE_WAIT,
		LAST_ACK 
	};


	struct buf_block
	{
		unsigned int seq_num;
		unsigned int ack_num;
		size_t data_size;
		Packet* packet;
	};

	struct write_block
	{
		/* data */
        UUID syscall_UUID;
        void* buffer;
        size_t current_size;
		std::list <struct buf_block> write_buffer;
		unsigned int buf_len = 0;
		unsigned int max_ack_num = 0;
        unsigned int peer_cwnd = 1;// Don't forget MSS
        
        /*
        //change peer cwnd to value.
        void change_peer_cwnd(unsigned int value){
            this->peer_cwnd = value;
        }
        //return write buffer's length.
        unsigned int len_write_buffer(){
            return this->buf_len;
        }
        */

        //return true if buffer is full.
        bool is_full_write_buffer(){
            return this->buf_len>=this->peer_cwnd;
        }
		//push_write_buffer: push new block into write buffer
		void push_write_buffer(int* SEQ_NUM, Packet* packet, size_t data_size){
			struct buf_block new_block;
			new_block.seq_num = (unsigned int)*SEQ_NUM;
			new_block.ack_num = (unsigned int)*SEQ_NUM + data_size;
			*SEQ_NUM = new_block.ack_num;
			new_block.data_size = data_size;
			new_block.packet = packet;
			this->write_buffer.push_back(new_block);
			this->buf_len++;
			return;
		}
		//get_ack_write_buffer: find the block having ACK_NUM, return the iter
		std::list<struct buf_block>::iterator get_ack_write_buffer(unsigned int ACK_NUM){
			std::list<struct buf_block>::iterator iter = this->write_buffer.begin();
			for(iter; iter != this->write_buffer.end();iter++){
				if(iter->ack_num == ACK_NUM)
					return iter;
			}
			return this->write_buffer.end();
		}
		//pop_acked_write_buffer: pop the buffer until acked one
		bool pop_acked_write_buffer(unsigned int ACK_NUM){
			//ignore if smaller than already acked num
			if(ACK_NUM <= this->max_ack_num){
				return false;
			}
			std::list<struct buf_block>::iterator iter = this->get_ack_write_buffer(ACK_NUM);
			if(iter == this->write_buffer.end()){
				return false;
			}
			else{
				this->write_buffer.erase(this->write_buffer.begin(),++iter);
				this->buf_len = this->write_buffer.size();
				this->max_ack_num = ACK_NUM;
				return true;
			}
		}
	};

	struct accept_param_container{
			UUID syscallUUID;
			//int pid;
			//int server_sock_fd;
			struct sockaddr* client_addr;
			socklen_t* client_len;
		};

	//Made for timer
	struct timer_idx{
		int pid;
		int fd;
	};
	/* TCP CONTEXT */
	struct tcp_context {
		int pid;
		int socket_fd;
		uint32_t src_addr;
		unsigned short int src_port;
		uint32_t dest_addr;
		unsigned short int dest_port;
		bool is_bound = false;
		TCP_STATE tcp_state = CLOSED;
		int seq_num;
		int fin_num;
		struct accept_param_container ap_cont;
		std::list< struct tcp_context > pending_conn_list;
		std::list< struct tcp_context > estb_conn_list;
		unsigned int backlog;
		unsigned int accept_cnt = 0;
		bool fin_ready = false;
		bool ack_ready = false;
        struct write_block write_context;
	};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	/* list of socket_blocks */
	std::list< struct tcp_context > tcp_list;
	int seq_num = 0;
	int port = 2000;
private:
	virtual void timerCallback(void* payload) final;
	/* Assignment */
	void syscall_socket(UUID syscallUUID, int pid, int param1_int, int param2_int);
	void syscall_close(UUID syscallUUID, int pid, int param1_int);
	void syscall_bind(UUID syscallUUID, int pid, int param1_int, struct sockaddr* param2_ptr, socklen_t param3_int);
	bool check_overlap(int fd, sockaddr* addr, int pid);
	void syscall_getsockname(UUID syscallUUID,int pid,int param1_int, struct sockaddr* param2_ptr, socklen_t* param3_ptr);
	void syscall_getpeername(UUID syscallUUID,int pid,int param1_int, struct sockaddr* param2_ptr, socklen_t* param3_ptr);
	void syscall_connect(UUID syscallUUID, int pid, int client_socket, struct sockaddr* connecting_addr, socklen_t len);
	void syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
	void syscall_accept(UUID syscallUUID, int pid, int param1_int,struct sockaddr* param2_ptr, socklen_t* param3_ptr);
	void add_tcplist(int fd, uint32_t addr, unsigned short int port, int pid);
	void remove_tcplist(int fd,int pid);
	std::list< struct tcp_context >::iterator find_tcplist(int fd, int pid);
	std::list<struct tcp_context>::iterator find_listen(uint32_t addr, uint16_t port);
	std::list<struct tcp_context>::iterator find_client(uint32_t addr, uint16_t port);
	std::list<struct tcp_context>::iterator get_tcp_state(uint32_t src_addr, uint16_t src_port, uint32_t dest_addr, uint16_t dest_port);
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
