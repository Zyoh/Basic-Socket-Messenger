from utils import sha256
import threading
import argparse
import socket
import json


class Message:
	@classmethod
	def from_json(cls, data):
		return cls(data["username"], data["password"], data["message"])

	def __init__(self, username: str, password: str, content: str):
		self.username = username
		self.password = password
		self.content = content
	
	def __eq__(self, o: object) -> bool:
		return \
			(self.username == o.username)\
			(self.password == o.password)\
			(self.content == o.content)

	@property
	def user_id(self) -> str:
		return sha256(f"{self.username}#{self.password}")


class DataBaseThatIsntSQLCuzImLAzy(dict):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self["history"] = []
	
	def add_message(self, message: Message):
		self["history"].append(message)
	
	def last_message(self) -> Message | None:
		if len(self["history"]) > 0:
			return self["history"][-1]


class Server:
	def __init__(self, ip: str, port: int):
		self.__ip = ip
		self.__port = port
		self.alive = False
		self.db = DataBaseThatIsntSQLCuzImLAzy()
		self.connections = []

	@property
	def ip(self) -> str:
		return self.__ip

	@property
	def port(self) -> int:
		return self.__port

	def __enter__(self):
		self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.__socket.bind((self.ip, self.port))
		self.__socket.listen()
		return self.__socket

	def __exit__(self, t, v, tb):
		self.__socket.close()
		self.__socket = None

	def run(self):
		try:
			with self as s:
				s.settimeout(0.2)
				self.alive = True
				while self.alive:
					try:
						conn, addr = s.accept()
						threading.Thread(target=self._connection_listener, args=(conn, addr), daemon=True).start()
						if conn not in self.connections:
							self.connections.append(conn)
					except socket.timeout:
						continue
		except KeyboardInterrupt:
			self.alive = False

	def _connection_listener(self, conn, addr):
		with conn:
			while True:
				data = conn.recv(1024)
				if not data:
					break

				self._handle_event(data, conn, addr)
	
	def _handle_event(self, data, conn, addr):
		data = str(data, encoding="utf8")
		data = json.loads(data)

		msg = Message.from_json(data)
		if msg.password is None or len(msg.password) < 16:
			return

		out = {
			"name": f"{msg.username}#{msg.user_id[:6]}",
			"message": msg.content
		}

		for c in self.connections:
			if c != conn:
				try:
					c.sendall(bytes(json.dumps(out), encoding="utf8"))
				except:
					continue

		if (previous_message := self.db.last_message()) and (msg.user_id == previous_message.user_id):
			out = f"> {msg.content}"
		else:
			out = f"\n{out['name']}\n> {out['message']}"
		print(out)

		self.db.add_message(msg)



def main():
	parser = argparse.ArgumentParser(description="Server application.")
	parser.add_argument("--ip", type=str, help="Server's IP address.", default="127.0.0.1")
	parser.add_argument("--port", type=int, help="Server's port.", default=12288)
	args = parser.parse_args()

	server = Server(args.ip, args.port)
	server.run()

if __name__ == "__main__":
	main()
