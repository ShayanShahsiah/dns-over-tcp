import socks

class UnableToParseError(RuntimeError):
	pass

def parse_addr(addr: str, default_port=9080) -> tuple[str, int]:
	host, sep, port_s = addr.partition(':')
	if sep:
		if not host:  # e.g. ':1080'
			host = '0.0.0.0'

		try:
			port = int(port_s)
		except ValueError:
			raise UnableToParseError('Invalid address format')
	else:
		if not host:
			raise UnableToParseError('Invalid address format')
		port = default_port

	return host, port

def parse_proxy(proxy: str, 
			default_proxy_type=socks.HTTP,
			default_http_port=8080, 
			default_socks_port=1080
			) -> tuple[int, str, int]:
	proxy_type_s, sep, addr = proxy.rpartition('://')
	if sep:
		try:
			proxy_type = socks.PROXY_TYPES[proxy_type_s.upper()]
		except KeyError:
			raise UnableToParseError('Invalid proxy type')
	else:
		proxy_type = default_proxy_type
	
	host, port = parse_addr(addr, 
			default_port=default_http_port if proxy_type == socks.HTTP else default_socks_port)

	return proxy_type, host, port

if __name__ == '__main__':
	import sys
	args = sys.argv[1:]

	print(parse_proxy(args[0]))