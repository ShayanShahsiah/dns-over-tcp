import errno
import logging
import socket
from contextlib import suppress
from random import choice
from select import select

import pylru

NAME_SERVERS = [
	('208.67.222.222', 53),
	('208.67.220.220', 53),
	('1.1.1.1', 53),
	('1.0.0.1', 53),
]

BUF_SIZE = 4096
DNS_HEADER_SIZE = 12
DNS_QUESTION_SIZE = 8
DNS_ANSWER_SIZE = 18

Address = tuple[str, int]

class Querier:
	def __init__(self, nameservers) -> None:
		self.nameservers = nameservers
		self._init_socket()
		self.is_connected = False

		self.out_buf = bytearray()  # Outgoing TCP DNS queries
		self.in_buf = bytearray()  # Incoming TCP DNS responses
		self.recepients: list[Address] = []

	def _init_socket(self) -> None:
		if PROXY:
			import socks
			self.socket = socks.socksocket()
			self.socket.set_proxy(*PROXY)
		else:
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		self.socket.setblocking(False)
		with suppress(BlockingIOError):
			self.nameserver = choice(self.nameservers)
			self.socket.connect(self.nameserver)

	def check_connected(self) -> None:
		try:
			self.socket.getpeername()  # TODO: OSError: [Errno 22] Invalid argument
		except OSError as e:
			if e.errno != errno.ENOTCONN:
				raise
		else:
			self.is_connected = True
			logging.debug('Querier to {}:{} connected!'.format(*self.nameserver))

	def make_query(self, query: bytes, recepient: Address) -> None:
		self.out_buf += len(query).to_bytes(2) + query
		self.recepients.append(recepient)

	def want_read(self) -> bool:
		if not (len(self.in_buf) < BUF_SIZE):
			logging.warning('Buffer full!')
		return self.is_connected and len(self.in_buf) < BUF_SIZE

	def want_write(self) -> bool:
		return self.is_connected and len(self.out_buf) > 0

	def read_tcp(self) -> tuple[bytes, Address] | None:
		try:
			stuff = self.socket.recv(BUF_SIZE - len(self.in_buf))  # TODO: TimeoutError: [Errno 60] Operation timed out
			if stuff:
				self.in_buf += stuff
			else:
				raise ConnectionResetError
		except ConnectionResetError:
			logging.debug('Querier to {}:{} disconnected!'.format(*self.nameserver))
			self.socket.close()
			self._init_socket()
			self.is_connected = False
			self.out_buf.clear()
			self.in_buf.clear()
			self.recepients.clear()
			return None
		else:
			return self._check_for_response()

	def write_tcp(self) -> None:
		n = self.socket.send(self.out_buf)
		self.out_buf = self.out_buf[n:]

	def _check_for_response(self) -> tuple[bytes, Address] | None:
		"""Checks to see if a full respose has been received
		"""
		if len(self.in_buf) < 2:
			return

		response_size = 2 + int.from_bytes(self.in_buf[:2])
		if len(self.in_buf) < response_size:
			return

		resp, self.in_buf = self.in_buf[:response_size], self.in_buf[response_size:]
		return bytes(resp[2:]), self.recepients.pop(0)


def req_from_resp(resp: bytes) -> bytes:
	req = bytearray(resp)
	req[2] &= 0b0000_0001  # Only keep RD (recursion desired)
	req[3] = 0
	n_quests = int.from_bytes(req[4:6])
	if n_quests != 1:
		raise NotImplementedError
	for idx in range(6, 12):
		req[idx] = 0
	idx = 12
	while (jump := req[idx]):
		idx += 1 + jump
	idx += 1 + 4
	return bytes(req[:idx])

def decode_domain(dns: bytes) -> str:
	res = bytearray(dns[12:])
	idx = 0
	while (jump := res[idx]):
		res[idx:idx+1] = b'.'
		idx += 1 + jump
	return res[1:idx].decode()

def serve():
	queriers = [Querier(NAME_SERVERS) for _ in range(8)]
	cache = pylru.lrucache(LRU_CACHE_SIZE)
	responses: list[tuple[bytes, Address]] = []

	global udp_sock
	udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udp_sock.setblocking(False)
	udp_sock.bind(BIND_ADDR)
	logging.info('Serving on {}:{}'.format(*BIND_ADDR))

	while True:
		readables = [udp_sock]
		for querier in queriers:
			if querier.want_read():
				readables.append(querier.socket)

		writables = []
		if responses:
			writables.append(udp_sock)
		for querier in queriers:
			if not querier.is_connected or querier.want_write():
				writables.append(querier.socket)

		read_rdy, write_rdy, _ = select(readables, writables, [], .5)

		if udp_sock in read_rdy:
			query, addr = udp_sock.recvfrom(BUF_SIZE)
			logging.debug(f'>> {decode_domain(query)}')
			tid, key = query[:2], query[2:]
			if key in cache:
				logging.debug('Using cached response')
				responses.append((tid + cache[key], addr))
			else:
				choice(queriers).make_query(query, addr)
		for querier in queriers:
			if querier.socket in read_rdy and querier.want_read():
				if (ret := querier.read_tcp()):
					resp, recepient = ret
					responses.append((resp, recepient))
					req = req_from_resp(resp)
					cache[req[2:]] = resp[2:]
		
		if udp_sock in write_rdy:
			resp, recepient = responses.pop()
			logging.debug(f'<< {decode_domain(resp)}')
			udp_sock.sendto(resp, recepient)
		for querier in queriers:
			if querier.socket in write_rdy:
				if not querier.is_connected:
					querier.check_connected()
				elif querier.want_write():
					querier.write_tcp()

if __name__ == '__main__':
	import argparse
	import parse_utils

	class HelpFormatter(argparse.HelpFormatter):
		def _format_action_invocation(self, action: argparse.Action) -> str:
			formatted = super()._format_action_invocation(action)
			if action.option_strings and action.nargs != 0:
				formatted = formatted.replace(
					f" {self._format_args(action, self._get_default_metavar_for_optional(action))}",
					"",
					len(action.option_strings) - 1,
				)

			return formatted
	
	parser = argparse.ArgumentParser(formatter_class=HelpFormatter)	
	parser.add_argument('-b', '--bind', metavar='<IP>[:PORT]', default='127.0.0.1:53',
					help='bind to IP (=127.0.0.1) and PORT (=9080)')
	parser.add_argument('-x', '--proxy', default=None,
					help='Pass TCP DNS requests through specified proxy; e.g. socks5://127.0.0.1:9050')
	parser.add_argument('-c', '--cache-size', type=int, default=512,
					help='LRU Cache size (=512)')
	parser.add_argument('-info', action='store_true', help='set debugging level to INFO')
	args = parser.parse_args()

	global BIND_ADDR
	BIND_ADDR = parse_utils.parse_addr(args.bind, default_port=53)

	global PROXY
	if args.proxy:
		PROXY = parse_utils.parse_proxy(args.proxy)
	else:
		PROXY = None

	global LRU_CACHE_SIZE
	LRU_CACHE_SIZE = args.cache_size

	if args.info:
		logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)
	else:
		logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

	try:
		serve()
	except KeyboardInterrupt:
		logging.info('Interrupt, exiting...')
	finally:
		udp_sock.close()