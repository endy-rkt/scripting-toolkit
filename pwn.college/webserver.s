.intel_syntax noprefix
.global _start

.section .data
AF_INET:
	.long 2

SOCK_STREAM:
	.long 1

IPPROTO_IP:
	.long 0	

SOCKADDR_IN:
	.2byte 0x02   			#AF_INET
	.2byte 0x5000 			#port=80
	.4byte 0x0    			#address=0.0.0.0 
	.8byte 0x0	  			#null padding

ADDR_LEN:
	.long 16

BACKLOG:
	.long 0

HEADER_OK:
	.ascii "HTTP/1.0 200 OK\r\n\r\n"
	HEADER_OK_LEN = . - HEADER_OK

BUFFER:
	.space	4096

PATH_BUFFER:
	.space	4096

BUFFER_LEN:
	.long	4096

O_RDONLY:
	.long  0

O_CREAT_WRONLY:
	.long 0x0041

.section .text

_start:
	#create space to save variable
	push rbp
	mov rbp, rsp
	sub	rsp, 0x30

	socket:
		mov edi, dword ptr [AF_INET]
		mov esi, dword ptr [SOCK_STREAM]
		mov edx, dword ptr [IPPROTO_IP]
		mov rax, 41
		syscall
	
	#check socket exist
	cmp	rax, 0x0
	jle exit_failure

	#store socket fd
	mov	dword ptr [rsp], eax   #socket fd

	bind:
		mov	edi, dword ptr [rsp]
		mov	rsi, offset SOCKADDR_IN
		mov	edx, dword ptr [ADDR_LEN]
		mov	rax, 49	
		syscall
	
	#check bind sucess
	cmp	rax, 0x0
	jb exit_failure

	listen:
		mov edi, dword ptr [rsp]
		mov esi, dword ptr [BACKLOG]
		mov rax, 50 
		syscall

	#check listen error
	cmp rax, 0x0
	jne exit_failure

	server_loop:
		accept:
			mov edi, dword ptr [rsp]
			mov rsi, 0
			mov rdx, 0
			mov rax, 43
			syscall

		#check accept error
		cmp rax, 0x0
		jl not_storing_socket

		store_client_socket:
			mov	dword ptr [rsp + 0x8], eax	 #client fd	
		
		fork:
			mov rax, 57
			syscall
		
		#check fork error
		cmp rax, 0x0
		je	child_process
		#close client fd
		mov edi, dword ptr [rsp + 0x8]
		call close_fd
		jmp server_loop

	child_process:
		#close socket fd
		mov edi, dword ptr [rsp]
		call close_fd

		get_request_:
		#set arg for read_request
		mov edi, dword ptr [rsp + 0x8]
		lea rsi, [rip + BUFFER]
		mov edx, dword ptr [BUFFER_LEN]
		call read_request
		#get read size
		mov dword ptr [rsp + 0x10], eax

		check_request_:
			mov dl, byte ptr [rip + BUFFER]
			cmp dl, 0x47
			je process_get_request
			jmp process_post_request

	process_post_request:
		#copy path
		xor rcx, rcx
		mov ebx, dword ptr [rsp + 0x10]
		lea rsi, [rip + PATH_BUFFER]
		lea rdi, [rip + BUFFER]
		copy_path:
			cmp ecx, ebx
			je copy_done
			mov	dl, byte ptr [rdi + rcx]
			mov byte ptr [rsi + rcx], dl
			inc rcx
			jmp copy_path

		copy_done:
			mov byte ptr [rsi + rcx], 0x0

		#get path
		call get_path
		cmp rax, 0x0
		jle exit_failure
		#create path
		mov rdi, rax
		mov esi, dword ptr [rip + O_CREAT_WRONLY]
		mov edx, 0777
		call open_path
		#check open
		cmp rax, 0x0
		jle exit_failure
		mov dword ptr [rsp + 0x20], eax
	
	write_post_data:
		lea rdi, [rip + PATH_BUFFER]
		xor rcx, rcx
		mov	eax, dword ptr [rsp + 0x10]
		
		loop_:
			cmp	ecx, eax
			jae clear_count

			mov dl, byte ptr [rdi + rcx]
			cmp dl, 0xa #\n 0xa
			je next
			inc rcx
			jmp loop_
			
			next:
				inc rcx
				cmp	ecx, edx
				jae clear_count
				mov dl, byte ptr [rdi + rcx]
				cmp dl, 0xd #\r 0xd
				je  done_
				inc rcx
				jmp loop_
		
		clear_count:
			xor ecx, ecx
			done_:
				inc rcx
				inc rcx
				lea rsi, [rdi + rcx]	
				
				xor rcx, rcx
				#remove_newline:
				#	mov dl, byte ptr[rsi + rcx]
				#	cmp dl, 0xd #\r
				#	je	remove_r
				#	inc rcx
				#	jmp remove_newline
#
				#remove_r:
				#	mov byte ptr [rsi + rcx], 0x0

				continue_write:
					xor rdx, rdx
				mov rdi, rsi
				call strlen	
				mov rdx, rax
				mov edi, dword ptr [rsp + 0x20]
				call write_response

				#close fd
				mov edi, dword ptr [rsp + 0x20]
				call close_fd

	send_header_:
			#set arg
			mov edi, dword ptr [rsp + 0x8]
			lea rsi, [rip + HEADER_OK]
			mov edx, HEADER_OK_LEN
			call write_response
			#close client fd
			mov edi, dword ptr [rsp + 0x8]
			call close_fd
	jmp exit_success

	process_get_request:
		get_request:
			#get path
			call get_path
			cmp rax, 0x0
			jle exit_failure
			#open path
			mov rdi, rax
			mov esi, dword ptr [rip + O_RDONLY]
			call open_path
			#check open
			cmp rax, 0x0
			jle exit_failure
			mov dword ptr [rsp + 0x20], eax		#path fd
		
		read_path_content:
			mov rdi, rax
			lea rsi, [rip + PATH_BUFFER]
			mov edx, dword ptr [rip + BUFFER_LEN]
			call read_request
			mov dword ptr [rsp + 0x28], eax   #path content length
			#close path fd
			mov edi, dword ptr [rsp + 0x20]
			call close_fd

		send_header:
			#set arg
			mov edi, dword ptr [rsp + 0x8]
			lea rsi, [rip + HEADER_OK]
			mov edx, HEADER_OK_LEN
			call write_response
			
		send_response:
			#set arg for write_response
			lea	rsi, [rip + PATH_BUFFER]
			mov edx, dword ptr [rsp + 0x28] 
			mov edi, dword ptr [rsp + 0x8]
			call write_response
			#check write done

			#close client fd
			mov edi, dword ptr [rsp + 0x8]
			call close_fd

		jmp exit_success

	not_storing_socket:
		#close socket fd
		mov edi, dword ptr [rsp]
		call close_fd

	exit_success:
		#clean up stack
		mov	rsp, rbp
		pop rbp
		
		#exit
		mov rdi, 0
		mov rax, 60
		syscall

	exit_failure:
		#clean up stack
		mov	rsp, rbp
		pop rbp
		
		#exit
		mov rdi, 1
		mov rax, 60
		syscall
		
	read_request:
		mov	rax, 0
		syscall
		ret
	
	write_response:
		mov rax, 1
		syscall
		ret

	close_fd:
		mov rax, 3
		syscall
		ret
	
	open_path:
		mov	rax, 2
		syscall
		ret
	
	strlen:
		mov rax, 0
		test rdi, rdi
		je done
		loop:
			mov dl, byte ptr [rdi + rax]
			test dl, dl
			je	done
			inc rax
			jmp loop

		done:
			ret

	get_path:
		#check read length
		mov eax, dword ptr [rsp + 0x10]
		cmp rax, 0x0
		jle exit_get_path

		#init register
		mov	rcx, 0
		lea rdi, [rip + BUFFER]
		mov edx, dword ptr [rsp + 0x10]  #max len

		#get first space
		remove_first_space:
			mov dl, byte ptr [rdi + rcx]
			cmp rcx, rdx
			ja	done_trim
			inc rcx
			cmp dl, 0x20 #is_space
			jne remove_first_space

		lea rdi, [rdi + rcx]
		mov rcx, 0
		remove_second_space:
			mov dl, byte ptr [rdi + rcx]
			cmp rcx, rdx
			ja	done_trim
			inc rcx
			cmp dl, 0x20 #is_space
			jne remove_second_space
			dec rcx
			mov byte ptr [rdi + rcx], 0x0
		
		exit_get_path:
			nop
		done_trim:
			mov qword ptr [rsp + 0x18], rdi	#path address ptr
			mov rax, rdi
		ret
