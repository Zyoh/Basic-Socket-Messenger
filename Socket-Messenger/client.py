from utils import sha256
import threading
import argparse
import socket
import json


class Client:
	def __init__(self, ip: str, port: int, username: str, password: str):
		self.__ip = ip
		self.__port = port
		
		self.alive = False

		self.username = username
		self.password = sha256(password)

	@property
	def ip(self) -> str:
		return self.__ip

	@property
	def port(self) -> int:
		return self.__port

	def __enter__(self):
		self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.__socket.connect((self.ip, self.port))
		return self.__socket

	def __exit__(self, t, v, tb):
		self.__socket.close()
		self.__socket = None

	def run(self):
		with self as s:
			s.settimeout(3)
			try:
				threading.Thread(target=self._track_other_messages, args=(s,), daemon=True).start()
				while True:
					message = input(f"({self.username})>_")
					s.sendall(bytes(json.dumps({
						"message": message, 
						"username": self.username, 
						"password": self.password
					}), encoding="utf8"))
			except KeyboardInterrupt:
				pass

	def _track_other_messages(self, conn):
		while True:
			try:
				data = conn.recv(1024)
				data = str(data, encoding="utf8")
				data = json.loads(data)

				name, message = data["name"], data["message"]

				print(f"\r({name})>_{message}")
			except KeyboardInterrupt:
				break
			except:
				continue


def main():
	parser = argparse.ArgumentParser(description="Client application.")
	parser.add_argument("--username", "-u", type=str, help="Your username, visible to everyone.")
	parser.add_argument("--password", "-p", type=str, help="Your password, visible as SHA256 hash to everyone.", default=None)
	parser.add_argument("--ip", type=str, help="Server's IP address.", default="127.0.0.1")
	parser.add_argument("--port", type=int, help="Server's port.", default=12288)
	args = parser.parse_args()

	client = Client(args.ip, args.port, args.username, args.password)
	client.run()

if __name__ == "__main__":
	main()
